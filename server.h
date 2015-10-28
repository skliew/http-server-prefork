#ifndef SERVER_H
#define SERVER_H

#include <unistd.h>

typedef struct {
    int sockfd;
    int n_children;
    pid_t* pids;
} server;

server* server_new(int, int);
int server_stop(server*);
int server_start(server*);
int server_destroy(server*);

#endif
