#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <ncurses.h>
#include <locale.h>
#include <openssl/evp.h>

#define MAX_MSG_SIZE 40

int sockfd;
WINDOW *my_win;
char *user_name;
unsigned char key[32] = "0123456789abcdef0123456789abcdef";

pthread_mutex_t ncurses_mutex;

int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *aad, int aad_len, const unsigned char *key, const unsigned char *iv, int iv_len, unsigned char *ciphertext, unsigned char *tag) {
  
  EVP_CIPHER_CTX *ctx;
  int len, ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return -1;
  };
  
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    return -1;
  };
  
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
    return -1;
  };

  if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
    return -1;
  };

  if (aad && aad_len > 0) {
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
      return -1;
    };
  };

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    return -1;
  };
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    return -1;
  };
  ciphertext_len += len;

  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    return -1;
  };

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
};

int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *aad, int aad_len, const unsigned char *tag, const unsigned char *key, const unsigned char *iv, int iv_len, unsigned char *plaintext) {
  
  EVP_CIPHER_CTX *ctx;
  int len, plaintext_len, ret;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return -1;
  };
  
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
    return -1;
  };

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
    return -1;
  };
 
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
    return -1;
  };

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag)) {
    return -1;
  };

  if (aad && aad_len > 0) {
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
      return -1;
    };
  };

  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    return -1;
  };
  plaintext_len = len;

  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  EVP_CIPHER_CTX_free(ctx);

  if (ret > 0) {
    plaintext_len += len;
    return plaintext_len;
  } else {
    return -1;
  };
};

void cleanup(void *arg) {
    if (close(sockfd) == -1) {
      return;
    };
};

typedef struct {
  int *sockfd;
  int *max_msg;
  char (*msg_queue)[MAX_MSG_SIZE];
  WINDOW *my_win;
} thread_args_struct;

int send_all(int sockfd, char *msg) {
  int target_value = strlen(msg);
  int cur_bytes;
  int tot_bytes = 0;
  while (tot_bytes < target_value) {
    cur_bytes = send(sockfd, msg + tot_bytes, target_value - tot_bytes, 0);
    if (cur_bytes == 0) {
      return 0;
    } else if (cur_bytes == -1) {
      return -1;
    };
    tot_bytes += cur_bytes;
  };
  return target_value;
};

int send_all2(int sockfd, char *msg, int target_value) {
  int cur_bytes;
  int tot_bytes = 0;
  while (tot_bytes < target_value) {
    cur_bytes = send(sockfd, msg + tot_bytes, target_value - tot_bytes, 0);
    if (cur_bytes == 0) {
      return -1;
    } else if (cur_bytes == -1) {
      return -1;
    };
    tot_bytes += cur_bytes;
    //printf("loop %d\n", tot_bytes);
  };
  return target_value;
};

int recv_all(int sockfd, char *buf, int len) {
  int received = 0;
  int ret;
  while (received < len) {
   ret = recv(sockfd, buf + received, len - received, 0);
   if (ret <= 0) {
     return ret;
   };
   received += ret;
  };
  return received;
};

void *recv_messages(void *x) {

  pthread_cleanup_push(cleanup, NULL);

  thread_args_struct *args = (thread_args_struct *)x;
  int n_bytes;
  int i;
  unsigned char ciphertext[MAX_MSG_SIZE];
  unsigned char local_buffer[MAX_MSG_SIZE];
  unsigned char tag[16];
  unsigned char iv[12];

  while (1) {
    n_bytes = recv_all(*args->sockfd, iv, 12);
    if (n_bytes <= 0) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      break;
    };
    n_bytes = recv_all(*args->sockfd, tag, 16);
    if (n_bytes <= 0) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      break;
    };
    memset(ciphertext, '\0', 40);
    n_bytes = recv_all(*args->sockfd, ciphertext, MAX_MSG_SIZE);
    if (n_bytes == -1) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      break;
    } else if (n_bytes == 0) {
      break;
    };

    memset(local_buffer, '\0', 40);
    n_bytes = aes_gcm_decrypt(
      ciphertext, 
      MAX_MSG_SIZE,
      NULL, 
      0,                 
      tag,
      key, 
      iv, 
      12,
      local_buffer
    );
    if (n_bytes < 0) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      break;
    };
    local_buffer[n_bytes - 1] = '\0';
    if (pthread_mutex_lock(&ncurses_mutex) != 0) {
      break;
    };

    i = 1;
    while (i < *args->max_msg) {
      strcpy(args->msg_queue[i - 1], args->msg_queue[i]);
      i += 1;
    };
    memcpy(args->msg_queue[*args->max_msg - 1], local_buffer, 40);
    args->msg_queue[*args->max_msg - 1][strlen(local_buffer)] = '\0';

    for (i = 0; i < *args->max_msg; i++) {
      wmove(my_win, i + 1, 2);             
      wclrtoeol(my_win);    
      mvwprintw(my_win, i + 1, 2, args->msg_queue[i]);
    };
    refresh();
    wbkgd(my_win, COLOR_PAIR(2));
    box(my_win, 0 , 0);
    wrefresh(my_win);
    refresh();
    if (pthread_mutex_unlock(&ncurses_mutex) != 0) {
      break;
    };
  };
  pthread_cleanup_pop(1);
  return NULL;
};

void fclose_exit(FILE **f) {
  if (*f) {
    fclose(*f);
  };
};

int main(int argc, char *argv[]) {
  FILE *f __attribute__((cleanup(fclose_exit))) = fopen("/dev/urandom", "rb");
  unsigned char iv[12];
  unsigned char ciphertext[MAX_MSG_SIZE];
  unsigned char tag[16];

  pthread_t messages_thread;
  struct addrinfo hints, *res;
  unsigned char msg[MAX_MSG_SIZE - 10];
  unsigned char usr_msg[MAX_MSG_SIZE];
  int msg_len;
  int use_it = 1;
  int status;
  int y, x;
  int local_max;
  int len_name;
  int max_msg;
  if (pthread_mutex_init(&ncurses_mutex, NULL) != 0) {
    return -1;
  };

  if (argc < 6) {
    return -1;
  };
  if (argc > 6) {
    return -1;
  };
  len_name = strlen(argv[3]);
  if (len_name > 8) {
    return -1;
  };
  user_name = argv[3];
  char after_user_name[3] = ": ";
  char final_user_name[len_name + 3];
  memset(final_user_name, '\0', len_name + 3);
  memcpy(final_user_name + len_name, after_user_name, 2);
  memcpy(final_user_name, user_name, len_name);
 
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;

  status = getaddrinfo(argv[1], argv[2], &hints, &res);
  if (status != 0) {
    return -1;
  };
 
  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1) {
    return -1;
  };
  
  status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &use_it, sizeof(int));
  if (status == -1) {
    return -1;
  };

  status = connect(sockfd, res->ai_addr, res->ai_addrlen);
  if (status == -1) {
    return -1;
  };

  freeaddrinfo(res);

  // Sending credentials
  char response[1];
  int ciphertext_len;
  char credentials[20];
  memset(credentials, '-', 20);
  memcpy(credentials, user_name, len_name);
  memcpy(credentials + 10, argv[4], strlen(argv[4]));
  fread(iv, 1, 12, f);
  if (send_all2(sockfd, iv, 12) == -1) {
    return -1;
  };
  max_msg = recv(sockfd, response, 1, 0);
  if (max_msg == 0) {
    clear();
    endwin();
    return -1;
  } else if (max_msg == -1) {
    clear();
    endwin();
    return -1;
  } else {
    if (response[0] != '1') {
      clear();
      endwin();
      return -1;
    };
  };

  ciphertext_len = aes_gcm_encrypt(
    credentials, 
    20,
    NULL, 
    0,                    
    key, 
    iv, 
    12,
    ciphertext, 
    tag
  );
  if (send_all2(sockfd, tag, 16) == -1) {
    return -1;
  };
  max_msg = recv(sockfd, response, 1, 0);
  if (max_msg == 0) {
    clear();
    endwin();
    return -1;
  } else if (max_msg == -1) {
    clear();
    endwin();
    return -1;
  } else {
    if (response[0] != '1') {
      clear();
      endwin();
      return -1;
    };
  };

  if (send_all2(sockfd, ciphertext, 20) == -1) {
    return -1;
  };
  max_msg = recv(sockfd, response, 1, 0);
  if (max_msg == 0) {
    clear();
    endwin();
    return -1;
  } else if (max_msg == -1) {
    clear();
    endwin();
    return -1;
  } else {
    if (response[0] != '1') {
      clear();
      endwin();
      return -1;
    };
  };

  // Sending chatroom name 
  char chatroom_name[10];
  memset(chatroom_name, '\0', 10);
  memcpy(chatroom_name, argv[5], strlen(argv[5]));
  fread(iv, 1, 12, f);
  if (send_all2(sockfd, iv, 12) == -1) {
    return -1;
  };
  max_msg = recv(sockfd, response, 1, 0);
  if (max_msg == 0) {
    close(sockfd);
    return -1;
  } else if (max_msg == -1) {
    close(sockfd);
    return -1;
  } else {
    if (response[0] != '1') {
      close(sockfd);
      return -1;
    };
  };
  ciphertext_len = aes_gcm_encrypt(
    chatroom_name, 
    10,
    NULL, 
    0,                    
    key, 
    iv, 
    12,
    ciphertext, 
    tag
  );
  if (send_all2(sockfd, tag, 16) == -1) {
    close(sockfd);
    return -1;
  };
  max_msg = recv(sockfd, response, 1, 0);
  if (max_msg == 0) {
    close(sockfd);
    return -1;
  } else if (max_msg == -1) {
    close(sockfd);
    return -1;
  } else {
    if (response[0] != '1') {
      close(sockfd);
      return -1;
    };
  };
  if (send_all2(sockfd, ciphertext, 10) == -1) {
    close(sockfd);
    return -1;
  };  
  max_msg = recv(sockfd, response, 1, 0);
  if (max_msg == 0) {
    close(sockfd);
    return -1;
  } else if (max_msg == -1) {
    close(sockfd);
    return -1;
  } else {
    if (response[0] != '1') {
      close(sockfd);
      return -1;
    };
  };

  setlocale(LC_ALL, "");
  initscr();
  if(has_colors() == FALSE) {
    endwin();
    close(sockfd);
    printf("Your terminal does not support color\n");
    return -1;
  };
  if(can_change_color() == FALSE) {
    endwin();
    close(sockfd);
    printf("Your terminal does not support changing color\n");
    return -1;
  };
  start_color();
  init_color(COLOR_WHITE, 555, 755, 755);
  init_pair(1, COLOR_BLACK, COLOR_WHITE);
  init_pair(2, COLOR_WHITE, COLOR_BLACK);
  bkgd(COLOR_PAIR(1));    
  curs_set(1);
  raw();
  noecho();
  keypad(stdscr, TRUE);
  getmaxyx(stdscr, y, x);
  my_win = newwin(y - (y / 4), x - (x / 5), 1, 1);
  wbkgd(my_win, COLOR_PAIR(2));
  mvprintw(0, 0, "':q' in message to Quit");
  wrefresh(my_win);

  int ref_max_msg = y - (y / 4) - 2;
  char msg_queue[ref_max_msg][MAX_MSG_SIZE];
  int i2;
  for (int i = 0; i < ref_max_msg ; i++) {
    for (i2 = 0; i2 + 1 < MAX_MSG_SIZE; i2++) {
      msg_queue[i][i2] = ' ';
    };
    msg_queue[i][MAX_MSG_SIZE - 1] = '\0';
  };

  snprintf(msg, MAX_MSG_SIZE, "System: %s is connected \n\0", argv[3]);
  // Sending connection message
  fread(iv, 1, 12, f);
  if (send_all2(sockfd, iv, 12) == -1) {
    clear();
    endwin();
    close(sockfd);
    return -1;
  };
  ciphertext_len = aes_gcm_encrypt(
    msg,
    MAX_MSG_SIZE,
    NULL, 
    0,                    
    key, 
    iv, 
    12,
    ciphertext, 
    tag
  );
  if (send_all2(sockfd, tag, 16) == -1) {
    clear();
    endwin();
    close(sockfd);
    return -1;
  };
  if (send_all2(sockfd, ciphertext, MAX_MSG_SIZE) == -1) {
    clear();
    endwin();
    close(sockfd);
    return -1;
  };  
  
  thread_args_struct thread_arg;
  thread_arg.sockfd = &sockfd;
  thread_arg.msg_queue = msg_queue;
  thread_arg.max_msg = &ref_max_msg;
  pthread_create(&messages_thread, NULL, recv_messages, (void *)&thread_arg);

  char cur_chr;
  int cnt_chr;
  int cursor_y;
  int cursor_x;

  while (1) {
    if (pthread_mutex_lock(&ncurses_mutex) != 0) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      pthread_cancel(messages_thread);
      pthread_join(messages_thread, NULL);
      return -1;
    };
    move(y - 2, 2); 
    printw("%s", "Message:                                                \0");
    clrtoeol();
    move(y - 2, 11); 
    refresh();
    if (pthread_mutex_unlock(&ncurses_mutex) != 0) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      pthread_cancel(messages_thread);
      pthread_join(messages_thread, NULL);
      return -1;
    };
    memset(msg, '\0', MAX_MSG_SIZE - 10);
    cnt_chr = 0;
    while ((cur_chr = getch()) != '\n' && cur_chr != '\r' && cnt_chr < MAX_MSG_SIZE - 10) {
      getyx(stdscr, cursor_y, cursor_x);
      if (cur_chr != KEY_BACKSPACE && cur_chr != 127 && cur_chr != 8 && cur_chr != 7) {
        addch(cur_chr);
        move(cursor_y, cursor_x + 1);
        msg[cnt_chr] = cur_chr;
        cnt_chr += 1;
      } else if (cnt_chr > 0) {
        getyx(stdscr, cursor_y, cursor_x);
        mvaddch(cursor_y, cursor_x - 1, ' ');
        move(cursor_y, cursor_x - 1);
        cnt_chr -= 1;
        msg[cnt_chr] = '\0';
      };
      clrtoeol();
      refresh();
    };
    if (msg[0] == ':' && msg[1] == 'q') {
      clear();
      endwin();
      close(sockfd);
      return 0;
    };
    local_max = strlen(msg);
    if (local_max + 11 < MAX_MSG_SIZE) {
      while (local_max + 11 < MAX_MSG_SIZE) {
        msg[local_max] = ' ';
        local_max += 1;
      };
      msg[local_max - 1] = '\0';
    } else {
        msg[MAX_MSG_SIZE - 11] = '\0';
    };
    memcpy(usr_msg + len_name + 2, msg, MAX_MSG_SIZE - 10);
    memcpy(usr_msg, final_user_name, len_name + 2);

    // Sending iv
    fread(iv, 1, 12, f);
    if (send_all2(sockfd, iv, 12) == -1) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      pthread_cancel(messages_thread);
      pthread_join(messages_thread, NULL);
      return -1;
    };
    ciphertext_len = aes_gcm_encrypt(
      usr_msg, 
      40,
      NULL, 
      0,                    
      key, 
      iv, 
      12,
      ciphertext, 
      tag
    );
    if (send_all2(sockfd, tag, 16) == -1) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      pthread_cancel(messages_thread);
      pthread_join(messages_thread, NULL);
      return -1;
    };
    // Sending ciphertext
    if (send_all2(sockfd, ciphertext, 40) == -1) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      pthread_cancel(messages_thread);
      pthread_join(messages_thread, NULL);
      return -1;
    }; 
  };

  pthread_mutex_destroy(&ncurses_mutex);
  pthread_cancel(messages_thread);
  pthread_join(messages_thread, NULL);

  return 0;
};


