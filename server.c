#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>

#include "server.h"

#define BACKLOG 20
#define DEBUG 0

#if DEBUG
#define debug(...) fprintf(stderr, __VA_ARGS__) 
#else
#define debug(...)
#endif

static pid_t child_new(server* s);

static int child_run(server* s) {
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    int newsockfd;
    int buffer[256];
    int r_size, w_size;

    for(;;) {
        if ((newsockfd = accept(s->sockfd, &addr, &addr_len)) < 0) {
            perror("accept");
            continue;
        }

        /* TODO Parse http */
        do {
            r_size = read(newsockfd, buffer, 256);
            if (r_size < 0) {
                perror("read");
                break;
            }
            w_size = write(newsockfd, "OK\n", 3);
            if (w_size < 0) {
                perror("write");
            }
        } while (r_size != 0);
    }
    return 0;
}

static pid_t child_new(server* s) {
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        child_run(s);
        return 0;
    } else if (pid < 0 ) {
        /* error */
        return pid;
    } else {
        /* parent */
        return pid;
    }
}

server* server_new(int portno, int n_children) {
    server* s = (server*)malloc(sizeof(server));
    struct sockaddr_in serv_addr;

    if (NULL == s)
        perror("malloc");

    s->n_children = n_children;

    if ((s->pids = (pid_t*)malloc(n_children * sizeof(pid_t))) == NULL) {
        perror("malloc pids");
        free(s);
        return NULL;
    }

    memset(s->pids, 0, n_children * sizeof(pid_t));

    if ((s->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(s->sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        close(s->sockfd);
        return NULL;
    }

    return s;
}

int server_start(server* s) {
    int i;

    if (listen(s->sockfd, BACKLOG) < 0) {
        perror("listen");
        return -1;
    }

    for (i = 0; i < s->n_children; i++) {
        s->pids[i] = child_new(s);
    }
    return 0;
}

int server_stop(server* s) {
    int i;
    for (i = 0; i < s->n_children; i++) {
        debug("Killing PID %d\n", s->pids[i]);
        int ret = kill(s->pids[i], SIGTERM);
        if (ret < 0)
            perror("kill");
    }
    return 0;
}

int server_destroy(server* s) {
    close(s->sockfd);
    free(s);
    return 0;
}
