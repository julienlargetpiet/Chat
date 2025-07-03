#include <stdio.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <ncurses.h>

#define MAX_MSG_SIZE 40

int sockfd;
WINDOW *my_win;
char *user_name;

pthread_mutex_t ncurses_mutex;

void cleanup(void *arg) {
    if (close(sockfd) == -1) {
      exit(1);
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
  tot_bytes = 0;
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

void *recv_messages(void *x) {

  pthread_cleanup_push(cleanup, NULL);

  thread_args_struct *args = (thread_args_struct *)x;
  int n_bytes;
  int i;
  char local_buffer[MAX_MSG_SIZE];
  while (1) {
    n_bytes = recv(*args->sockfd, local_buffer, MAX_MSG_SIZE, 0);
    if (n_bytes == -1) {
      endwin();
      pthread_mutex_destroy(&ncurses_mutex);
      exit(1);
    } else if (n_bytes == 0) {
      break;
    } else {
      local_buffer[n_bytes] = '\0';
      if (pthread_mutex_lock(&ncurses_mutex) != 0) {
        break;
      };
      i = 1;
      while (i < *args->max_msg) {
        strcpy(args->msg_queue[i - 1], args->msg_queue[i]);
        i += 1;
      };
      strcpy(args->msg_queue[*args->max_msg - 1], local_buffer);
      for (i = 0; i < *args->max_msg; i++) {

        mvwprintw(my_win, i + 1, 2, args->msg_queue[i]);
      };
      box(my_win, 0 , 0);
      wrefresh(my_win);
      wbkgd(my_win, COLOR_PAIR(2));    
      refresh();
      if (pthread_mutex_unlock(&ncurses_mutex) != 0) {
        break;
      };
    };
  };

  pthread_cleanup_pop(1);
  return NULL;
};

int main(int argc, char *argv[]) {
  pthread_t messages_thread;
  struct addrinfo hints, *res;
  char msg[MAX_MSG_SIZE - 10];
  char usr_msg[MAX_MSG_SIZE];
  int msg_len;
  int use_it = 1;
  int status;
  int y, x;
  int local_max;
  int len_name;
  if (pthread_mutex_init(&ncurses_mutex, NULL) != 0) {
    return -1;
  };

  if (argc < 4) {
    return -1;
  };
  if (argc > 4) {
    return -1;
  };
  len_name = strlen(argv[3]);
  if (len_name > 8) {
    return -1;
  };
  user_name = argv[3];
  char after_user_name[2] = ": ";
  char final_user_name[len_name + 2];
  memcpy(final_user_name + len_name, after_user_name, 2);
  memcpy(final_user_name, user_name, len_name);

  initscr();
  if(has_colors() == FALSE) {
    endwin();
    printf("Your terminal does not support color\n");
    exit(1);
  };
  if(can_change_color() == FALSE) {
    endwin();
    printf("Your terminal does not support changing color\n");
    exit(1);
  };
  start_color();
  init_color(COLOR_WHITE, 555, 755, 755);
  init_pair(1, COLOR_BLACK, COLOR_WHITE);
  init_pair(2, COLOR_WHITE, COLOR_BLACK);
  bkgd(COLOR_PAIR(1));    
  curs_set(1);
  cbreak();
  keypad(stdscr, TRUE);
  getmaxyx(stdscr, y, x);
  my_win = newwin(y - (y / 4), x - (x / 5), 1, 1);
  wbkgd(my_win, COLOR_PAIR(2));    
  wrefresh(my_win);

  int max_msg = y - (y / 4) - 2;
  char msg_queue[max_msg][MAX_MSG_SIZE];
  int i2;
  for (int i = 0; i < max_msg ; i++) {
    for (i2 = 0; i2 + 1 < MAX_MSG_SIZE; i2++) {
      msg_queue[i][i2] = ' ';
    };
    msg_queue[i][MAX_MSG_SIZE - 1] = '\0';
  };
 
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;

  status = getaddrinfo(argv[1], argv[2], &hints, &res);
  if (status != 0) {
    endwin();
    return -1;
  };

  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1) {
    endwin();
    return -1;
  };
 
  status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &use_it, sizeof(int));
  if (status == -1) {
    endwin();
    return -1;
  };

  status = connect(sockfd, res->ai_addr, res->ai_addrlen);
  if (status == -1) {
    endwin();
    return -1;
  };

  freeaddrinfo(res);

  thread_args_struct thread_arg;
  thread_arg.sockfd = &sockfd;
  thread_arg.msg_queue = msg_queue;
  thread_arg.max_msg = &max_msg;
  pthread_create(&messages_thread, NULL, recv_messages, (void *)&thread_arg);

  mvprintw(0, 0, "Ctrl-C to stop");
  snprintf(msg, MAX_MSG_SIZE, "System: %s is connected \n\0", argv[3]);
  if (send_all(sockfd, msg) == -1) {
    endwin();
    return -1;
  };

  while (1) {
    if (pthread_mutex_lock(&ncurses_mutex) != 0) {
      return -1;
    };
    move(y - 2, 2); 
    printw("%s", "Message:                                                \0");
    clrtoeol();
    move(y - 2, 11); 
    refresh();
    if (pthread_mutex_unlock(&ncurses_mutex) != 0) {
      return -1;
    };
    getstr(msg); 

    local_max = strlen(msg);
    if (local_max + 1 < MAX_MSG_SIZE) {
        while (local_max + 1 < MAX_MSG_SIZE) {
            msg[local_max] = ' ';
            local_max += 1;
        };
        msg[local_max] = '\0';
    } else {
        msg[MAX_MSG_SIZE - 1] = '\0';
    };
    memcpy(usr_msg + len_name + 2, msg, MAX_MSG_SIZE - 10);
    memcpy(usr_msg, final_user_name, len_name + 2);
    if (send_all(sockfd, usr_msg) == -1) {
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


