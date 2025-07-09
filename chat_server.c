#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <dirent.h>
#include <openssl/evp.h>

#define PORT "9034"  
#define MAX_ACCEPT_THREADS 100
#define MAX_CLIENTS 100
#define COLOR_BOLD  "\e[1m"
#define COLOR_OFF   "\e[m"
#define MAX_MSG_SIZE 40

char ref_credentials[MAX_CLIENTS][20];
FILE *f;

void end_func(int sign) {
  fclose(f);
  exit(0);
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

/*
 * Convert socket to IP address string.
 * addr: struct sockaddr_in or struct sockaddr_in6
 */
const char *inet_ntop2(void *addr, char *buf, size_t size)
{
    struct sockaddr_storage *sas = addr;
    struct sockaddr_in *sa4;
    struct sockaddr_in6 *sa6;
    void *src;

    switch (sas->ss_family) {
        case AF_INET:
            sa4 = addr;
            src = &(sa4->sin_addr);
            break;
        case AF_INET6:
            sa6 = addr;
            src = &(sa6->sin6_addr);
            break;
        default:
            return NULL;
    }

    return inet_ntop(sas->ss_family, src, buf, size);
}

/*
 * Return a listening socket.
 */
int get_listener_socket(void)
{
    int listener;     // Listening socket descriptor
    int yes=1;        // For setsockopt() SO_REUSEADDR, below
    int rv;

    struct addrinfo hints, *ai, *p;

    // Get us a socket and bind it
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) != 0) {
        fprintf(stderr, "pollserver: %s\n", gai_strerror(rv));
        exit(1);
    }

    for(p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol);
        if (listener < 0) {
            continue;
        }

        // Lose the pesky "address already in use" error message
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }

        break;
    }

    // If we got here, it means we didn't get bound
    if (p == NULL) {
        return -1;
    }

    freeaddrinfo(ai); // All done with this

    // Listen
    if (listen(listener, 10) == -1) {
        return -1;
    };

    return listener;
};

/*
 * Add a new file descriptor to the set.
 */
void add_to_pfds(struct pollfd **pfds, int newfd, int *fd_count,
        int *fd_size) {
    // If we don't have room, add more space in the pfds array
    if (*fd_count == *fd_size) {
        *fd_size *= 2; // Double it
        *pfds = realloc(*pfds, sizeof(**pfds) * (*fd_size));
    };

    (*pfds)[*fd_count].fd = newfd;
    (*pfds)[*fd_count].events = POLLIN; // Check ready-to-read
    (*pfds)[*fd_count].revents = 0;

    (*fd_count)++;
    printf("socket added to poll\n");
};

/*
 * Remove a file descriptor at a given index from the set.
 */
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count, char (**chatrooms_name)[10], char (**all_usernames)[10]) {
  (*fd_count)--;
  memset((*chatrooms_name)[i], '\0', 10);
  memset((*all_usernames)[i], '\0', 10);
  memcpy((*chatrooms_name)[i], (*chatrooms_name)[*fd_count], 10);
  memcpy((*all_usernames)[i], (*all_usernames)[*fd_count], 10);
  memset((*chatrooms_name)[*fd_count], '\0', 10);
  memset((*all_usernames)[*fd_count], '\0', 10);
  pfds[i] = pfds[*fd_count]; 
};

int accept_func(int newfd, int *fd_count, int *base_memory, char (**chatrooms_name)[10], char (**all_usernames)[10]) {
  unsigned char key[32] = "0123456789abcdef0123456789abcdef";
  unsigned char iv[12];
  unsigned char ciphertext[MAX_MSG_SIZE];
  unsigned char tag[16];
  char cur_chatroom_name[10];
  memset(cur_chatroom_name, '\0', 10);
  char credentials[20];
  memset(credentials, '-', 20);
  struct timeval timeout;
  int i;
  int nbytes;
  int is_ok = 0;
  char response[1];
  timeout.tv_sec = 1; 
  timeout.tv_usec = 0;
  setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  //Receive the IV credentials
  nbytes = recv_all(newfd, iv, 12);
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  };
  response[0] = '1';
  if (send(newfd, response, 1, 0) == -1) {
    close(newfd);
    return 0;
  };
  // Receive the tag credentials
  nbytes = recv_all(newfd, tag, 16);
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  };
  if (send(newfd, response, 1, 0) == -1) {
    close(newfd);
    return 0;
  };
  // Receive the ciphertext credentials
  nbytes = recv_all(newfd, ciphertext, 20);
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  };
  int decryptedtext_len = aes_gcm_decrypt(
    ciphertext, 
    20,
    NULL, 
    0,                 
    tag,
    key, 
    iv, 
    12,
    credentials
  );
  credentials[19] = '\0';
  if (decryptedtext_len < 0) {
    printf("Decryption failed! Authentication tag mismatch.\n");
    response[0] = '0';
    if (send(newfd, response, 1, 0) == -1) {
      close(newfd);
      return 0;
    }; 
    return 0;
  };
  for (i = 0; i < MAX_CLIENTS; i++) {
    if (memcmp(credentials, ref_credentials[i], 20) == 0) {
      is_ok = 1;
      break;
    };
  };
  if (!is_ok) {
    response[0] = '0';
    if (send(newfd, response, 1, 0) == -1) {
      close(newfd);
      return 0;
    };
    close(newfd);
    return 0;
  };
  if (send(newfd, response, 1, 0) == -1) {
    close(newfd);
    return 0;
  };
  int cmp_val = (*base_memory / (sizeof(char) * 10)) - (*fd_count) - 1;
  if (cmp_val < 0) {
    *base_memory *= 2;
    *chatrooms_name = realloc(*chatrooms_name, *base_memory);
  };
  // Receive the IV chatroom
  nbytes = recv_all(newfd, iv, 12);
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  };
  if (send(newfd, response, 1, 0) == -1) {
    close(newfd);
    return 0;
  };
  // Receive the tag chatroom
  nbytes = recv_all(newfd, tag, 16);
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  };
  if (send(newfd, response, 1, 0) == -1) {
    close(newfd);
    return 0;
  };
  // Receive the ciphertext chatroom
  nbytes = recv_all(newfd, ciphertext, 10);
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  };
  decryptedtext_len = aes_gcm_decrypt(
    ciphertext, 
    10,
    NULL, 
    0,                 
    tag,
    key, 
    iv, 
    12,
    cur_chatroom_name
  );
  if (decryptedtext_len <= 0) {
    response[0] = '0';
    if (send(newfd, response, 1, 0) == -1) {
      close(newfd);
      return 0;
    };
    return 0;
  };
  if (send(newfd, response, 1, 0) == -1) {
    close(newfd);
    return 0;
  };
  cur_chatroom_name[9] = '\0';
  memcpy((*chatrooms_name)[*fd_count], cur_chatroom_name, 10);
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  i = 0;
  while (credentials[i] != '-') {
    printf("%c", credentials[i]);
    i += 1;
  };
  printf("\n");
  memset((*all_usernames)[*fd_count], '\0', 10);
  memcpy((*all_usernames)[*fd_count], credentials, i);
  return 1;
};

/*
 * Handle incoming connections.
 */
void handle_new_connection(int listener, int *fd_count,
        int *fd_size, struct pollfd **pfds, int *base_memory, char (**chatrooms_name)[10], char (**all_usernames)[10])
{
    struct sockaddr_storage remoteaddr; // Client address
    socklen_t addrlen;
    int newfd;  // Newly accept()ed socket descriptor
    char remoteIP[INET6_ADDRSTRLEN];

    addrlen = sizeof remoteaddr;
    newfd = accept(listener, (struct sockaddr *)&remoteaddr,
            &addrlen);

    if (newfd == -1) {
        perror("accept");
    } else { 
        printf("pollserver: new connection from %s on socket %d\n",
                inet_ntop2(&remoteaddr, remoteIP, sizeof remoteIP),
                newfd);
        if (accept_func(newfd, fd_count, base_memory, chatrooms_name, all_usernames) == 1) {
          add_to_pfds(pfds, newfd, fd_count, fd_size);
        };
    }
}

/*
 * Handle regular client data or client hangups.
 */
void handle_client_data(int listener, int *fd_count, struct pollfd *pfds, int *pfd_i, char (**chatrooms_name)[10], FILE **f, char (**all_usernames)[10]) {
  unsigned char tag[16];
  unsigned char iv[12];
  char response[1] = {'1'};
  unsigned char ciphertext[MAX_MSG_SIZE] = {0};
  unsigned char buf2[40] = {0};
  memcpy(buf2, "System disconnection: ", 22);
  buf2[22] = ' ';
  char cur_chatroom_name[10];
  unsigned char key[32] = "0123456789abcdef0123456789abcdef";

  int nbytes = recv_all(pfds[*pfd_i].fd, iv, 12);

  int ref_name_size = strlen((*chatrooms_name)[*pfd_i]);
  int current_name_size;
  memcpy(cur_chatroom_name, (*chatrooms_name)[*pfd_i], ref_name_size);
  int j;
  int sender_fd = pfds[*pfd_i].fd;

  if (nbytes <= 0) { // Got error or connection closed by client
    if (nbytes == 0) {
      memcpy(buf2 + 23, (unsigned char*)(*all_usernames)[*pfd_i], strlen((*all_usernames)[*pfd_i]));
      buf2[39] = '\0';
      // Connection closed
      fread(iv, 1, 12, *f);
      nbytes = aes_gcm_encrypt(
        buf2, 
        40,
        NULL, 
        0,                    
        key, 
        iv, 
        12,
        ciphertext, 
        tag
      );
      if (nbytes <= 0) {
        return;        
      };

      for(j = 0; j < *fd_count; j++) {
        int dest_fd = pfds[j].fd;
        // Except the listener and ourselves
        if (dest_fd != listener && dest_fd != sender_fd) {
          current_name_size = strlen((*chatrooms_name)[j]);
          if (ref_name_size == current_name_size) {
            if (memcmp(cur_chatroom_name, (*chatrooms_name)[j], ref_name_size) == 0) {
              printf("sending disconnection message on socket %d %s\n", dest_fd, buf2);
              if (send_all2(dest_fd, iv, 12) == -1) {
                  perror("send");
              };
            };
          };
        };
      };
      for(j = 0; j < *fd_count; j++) {
        int dest_fd = pfds[j].fd;
        // Except the listener and ourselves
        if (dest_fd != listener && dest_fd != sender_fd) {
          current_name_size = strlen((*chatrooms_name)[j]);
          if (ref_name_size == current_name_size) {
            if (memcmp(cur_chatroom_name, (*chatrooms_name)[j], ref_name_size) == 0) {
              printf("sending disconnection message on socket %d %s\n", dest_fd, buf2);
              if (send_all2(dest_fd, tag, 16) == -1) {
                  perror("send");
              };
            };
          };
        };
      };
      for(j = 0; j < *fd_count; j++) {
        int dest_fd = pfds[j].fd;
        // Except the listener and ourselves
        if (dest_fd != listener && dest_fd != sender_fd) {
          current_name_size = strlen((*chatrooms_name)[j]);
          if (ref_name_size == current_name_size) {
            if (memcmp(cur_chatroom_name, (*chatrooms_name)[j], ref_name_size) == 0) {
              printf("sending disconnection message on socket %d %s\n", dest_fd, buf2);
              if (send_all2(dest_fd, ciphertext, 40) == -1) {
                  perror("send");
              };
            };
          };
        };
      };
    } else {
      perror("recv");
    };

    close(pfds[*pfd_i].fd); // Bye!

    del_from_pfds(pfds, *pfd_i, fd_count, chatrooms_name, all_usernames);

    // reexamine the slot we just deleted
    (*pfd_i)--;
 
  } else { // We got some good data from a client
    nbytes = recv_all(pfds[*pfd_i].fd, tag, 16);
    if (nbytes <= 0) {
      close(pfds[*pfd_i].fd);
      del_from_pfds(pfds, *pfd_i, fd_count, chatrooms_name, all_usernames);
      (*pfd_i)--;
      return;
    };
    nbytes = recv_all(pfds[*pfd_i].fd, ciphertext, 40);
    if (nbytes <= 0) {
      close(pfds[*pfd_i].fd);
      del_from_pfds(pfds, *pfd_i, fd_count, chatrooms_name, all_usernames);
      (*pfd_i)--;
      return;
    };

    for(j = 0; j < *fd_count; j++) {
      int dest_fd = pfds[j].fd;
      if (dest_fd != listener) {
        current_name_size = strlen((*chatrooms_name)[j]);
        if (ref_name_size == current_name_size) {
          if (memcmp(cur_chatroom_name, (*chatrooms_name)[j], ref_name_size) == 0) {
            printf("Sending iv on socket: %d\n", dest_fd);
            if (send_all2(dest_fd, iv, 12) == -1) {
                perror("send");
            };
          };
        };
      };
    };
    for(j = 0; j < *fd_count; j++) {
      int dest_fd = pfds[j].fd;
      if (dest_fd != listener) {
        current_name_size = strlen((*chatrooms_name)[j]);
        if (ref_name_size == current_name_size) {
          if (memcmp(cur_chatroom_name, (*chatrooms_name)[j], ref_name_size) == 0) {
            printf("Sending tag on socket: %d\n", dest_fd);
            if (send_all2(dest_fd, tag, 16) == -1) {
                perror("send");
            };
          };
        };
      };
    };
    for(j = 0; j < *fd_count; j++) {
      int dest_fd = pfds[j].fd;
      if (dest_fd != listener) {
        current_name_size = strlen((*chatrooms_name)[j]);
        if (ref_name_size == current_name_size) {
          if (memcmp(cur_chatroom_name, (*chatrooms_name)[j], ref_name_size) == 0) {
            printf("Sending ciphertext on socket: %d\n", dest_fd);
            if (send_all2(dest_fd, ciphertext, 40) == -1) {
                perror("send");
            };
          };
        };
      };
    };
  };
};

/*
 * Process all existing connections.
 */
void process_connections(int listener, int *fd_count, int *fd_size, struct pollfd **pfds, int *base_memory, char (**chatrooms_name)[10], FILE **f, char (**all_usernames)[10]) {
    for(int i = 0; i < *fd_count; i++) {

        // Check if someone's ready to read
        if ((*pfds)[i].revents & (POLLIN | POLLHUP)) {
            // We got one!!

            if ((*pfds)[i].fd == listener) {
                // If we're the listener, it's a new connection
                handle_new_connection(listener, fd_count, fd_size,
                        pfds, base_memory, chatrooms_name, all_usernames);
            } else {
                // Otherwise we're just a regular client
                handle_client_data(listener, fd_count, *pfds, &i, chatrooms_name, f, all_usernames);
            };
        };
    };
};

/*
 * Main: create a listener and connection set, loop forever
 * processing connections.
 */
int main(void) {

  f = fopen("/dev/urandom", "rb");
  int i = 0;
  char *filename = "credentials.txt";
  int nb_bytes = strlen(filename);
  DIR *dir = opendir(".");
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strlen(entry->d_name) == nb_bytes) {
      if (memcmp(filename, entry->d_name, nb_bytes) == 0) {
        break;
      };
    };
  };
  closedir(dir);
  if ((entry = readdir(dir)) == NULL) {
    printf("The file does not exist.\n");
    return -1;
  };
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    printf(COLOR_BOLD "File can't be opened in write mode\n" COLOR_OFF);
    return -1;
  };
  while (fgets(ref_credentials[i], 20, file)) {
    i += 1;
  };
  fclose(file);  

  int listener;     // Listening socket descriptor
  signal(SIGINT, end_func);

  // Start off with room for 5 connections
  // (We'll realloc as necessary)
  int fd_size = 5;
  int fd_count = 0;
  int base_memory = sizeof(char) * 10 * 2;
  char (*chatrooms_name)[10] = malloc(base_memory);
  struct pollfd *pfds = malloc(sizeof *pfds * fd_size);

  // Set up and get a listening socket
  listener = get_listener_socket();

  if (listener == -1) {
      fprintf(stderr, "error getting listening socket\n");
      exit(1);
  };

  // Add the listener to set;
  // Report ready to read on incoming connection
  pfds[0].fd = listener;
  pfds[0].events = POLLIN;
  char (*all_usernames)[10] = malloc(MAX_CLIENTS * 10 * sizeof(char));

  fd_count = 1; // For the listener

  puts("pollserver: waiting for connections...");

  // Main loop
  for(;;) {
      int poll_count = poll(pfds, fd_count, -1);

      if (poll_count == -1) {
          perror("poll");
          exit(1);
      };

      // Run through connections looking for data to read
      process_connections(listener, &fd_count, &fd_size, &pfds, &base_memory, &chatrooms_name, &f, &all_usernames);
  };

  free(pfds);
};


