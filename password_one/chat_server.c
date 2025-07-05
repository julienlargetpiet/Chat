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
#include <pthread.h>
#include <signal.h>
#include <dirent.h>

#define PORT "9034"  
#define MAX_ACCEPT_THREADS 100
#define MAX_CLIENTS 100
#define COLOR_BOLD  "\e[1m"
#define COLOR_OFF   "\e[m"

pthread_t accept_thread;
int pthread_alrd = 0;
char ref_credentials[MAX_CLIENTS][20];

void end_func(int sign) {
  pthread_join(accept_thread, NULL);
  exit(0);
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
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count) {
    // Copy the one from the end over this one
    pfds[i] = pfds[*fd_count-1];

    (*fd_count)--;
};

int accept_func(int newfd) {
  char credentials[20];
  memset(credentials, '-', 20);
  struct timeval timeout;
  int i;
  int is_ok = 0;
  timeout.tv_sec = 1; 
  timeout.tv_usec = 0;
  setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  int nbytes = recv(newfd, credentials, 20, 0);
  credentials[19] = '\0';
  char response[1];
  if (nbytes == 0) {
    printf("Connection lost for %d\n", newfd);
    close(newfd);
    return 0;
  } else if (nbytes == -1) {
    printf("Error for %d\n", newfd);
    close(newfd);
    return 0;
  } else {
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
    response[0] = '1';
    if (send(newfd, response, 1, 0) == -1) {
      close(newfd);
      return 0;
    };
  };
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  return 1;
};

/*
 * Handle incoming connections.
 */
void handle_new_connection(int listener, int *fd_count,
        int *fd_size, struct pollfd **pfds)
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
        if (accept_func(newfd) == 1) {
          add_to_pfds(pfds, newfd, fd_count, fd_size);
        };
    }
}

/*
 * Handle regular client data or client hangups.
 */
void handle_client_data(int listener, int *fd_count,
        struct pollfd *pfds, int *pfd_i)
{
    char buf[256];    
    char buf2[25] = "Someone has disconnected\0";

    int nbytes = recv(pfds[*pfd_i].fd, buf, sizeof buf, 0);

    int sender_fd = pfds[*pfd_i].fd;

    if (nbytes <= 0) { // Got error or connection closed by client
        if (nbytes == 0) {
            // Connection closed
            printf("pollserver: socket %d hung up\n", sender_fd);
            for(int j = 0; j < *fd_count; j++) {
              int dest_fd = pfds[j].fd;

              // Except the listener and ourselves
              if (dest_fd != listener) {
                printf("sending on socket %d %s\n", dest_fd, buf);
                if (send(dest_fd, buf2, 25, 0) == -1) {
                    perror("send");
                };
              };
            };
        } else {
            perror("recv");
        }

        close(pfds[*pfd_i].fd); // Bye!

        del_from_pfds(pfds, *pfd_i, fd_count);

        // reexamine the slot we just deleted
        (*pfd_i)--;

    } else { // We got some good data from a client
        printf("pollserver: recv from fd %d: %.*s \n", sender_fd,
                nbytes, buf);
        // Send to everyone!
        for(int j = 0; j < *fd_count; j++) {
            int dest_fd = pfds[j].fd;

            // Except the listener and ourselves
            if (dest_fd != listener) {
                printf("sending on socket %d %s\n", dest_fd, buf);
                if (send(dest_fd, buf, nbytes, 0) == -1) {
                    perror("send");
                };
            };
        };
    };
};

/*
 * Process all existing connections.
 */
void process_connections(int listener, int *fd_count, int *fd_size,
        struct pollfd **pfds) {
    for(int i = 0; i < *fd_count; i++) {

        // Check if someone's ready to read
        if ((*pfds)[i].revents & (POLLIN | POLLHUP)) {
            // We got one!!

            if ((*pfds)[i].fd == listener) {
                // If we're the listener, it's a new connection
                handle_new_connection(listener, fd_count, fd_size,
                        pfds);
            } else {
                // Otherwise we're just a regular client
                handle_client_data(listener, fd_count, *pfds, &i);
            };
        };
    };
};

/*
 * Main: create a listener and connection set, loop forever
 * processing connections.
 */
int main(void) {

  int i = 0;
  char *filename = "credentials.txt";
  int nb_bytes = strlen(filename);
  DIR *dir = opendir(".");
  struct dirent *entry;
  //printf("nb_bytes: %d\n", nb_bytes);
  while ((entry = readdir(dir)) != NULL) {
    //printf("current file: %s %d\n", entry->d_name, strlen(entry->d_name));
    if (strlen(entry->d_name) == nb_bytes) {
      //printf("ok\n");
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
      process_connections(listener, &fd_count, &fd_size, &pfds);
  };

  free(pfds);
};


