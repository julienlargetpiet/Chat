#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>

#define COLOR_BOLD  "\e[1m"
#define COLOR_OFF   "\e[m"

char *prepend_charr(char *x1, char *x2) {
  char *rtn_charr = malloc(21);
  memcpy(rtn_charr + 10, x2, 10);
  memcpy(rtn_charr, x1, 10);
  rtn_charr[20] = '\n';
  return rtn_charr;
};

int main() {
  char filename[20];
  char username[10];
  char password[10];
  int i;
  printf(COLOR_BOLD "Enter chatroom file: " COLOR_OFF);
  fflush(stdout);
  int nb_bytes;
  if (fgets(filename, 20, stdin) != NULL) {
    nb_bytes = strlen(filename);
  } else {
    return -1;
  };
  nb_bytes -= 1;
  filename[nb_bytes] = '\0';
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
  printf(COLOR_BOLD "Enter username: " COLOR_OFF);
  fflush(stdout);
  if (fgets(username, 10, stdin) != NULL) {
    nb_bytes = strlen(username);
  } else {
    return -1;
  };
  i = 0;
  while (i < strlen(username)) {
    if (username[i] == '-') {
      printf("All characters allowed apart from '-'");
      return -1;
    };
    i += 1;
  };
  i = nb_bytes - 1;
  while (i < 10) {
    username[i] = '-';
    i += 1;
  };
  printf(COLOR_BOLD "Enter password: " COLOR_OFF);
  fflush(stdout);
  if (fgets(password, 10, stdin) != NULL) {
    nb_bytes = strlen(password);
  } else {
    return -1;
  };
  i = nb_bytes - 1;
  while (i < 10) {
    password[i] = '-';
    i += 1;
  };
  char *content_to_add = prepend_charr(username, password);
  printf("new credentials: %s\n", content_to_add);
  FILE *file = fopen(filename, "a");
  if (file == NULL) {
    printf( COLOR_BOLD "File can't be opened in append mode\n" COLOR_OFF);
    return -1;
  };
  fprintf(file, content_to_add);
  fclose(file);  
  return 0;
};


