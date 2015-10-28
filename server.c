#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>

#include "server.h"
#include "picohttpparser/picohttpparser.h"

#define BACKLOG 20
#define DEBUG 1

#if DEBUG
#define debug(...) fprintf(stderr, __VA_ARGS__) 
#else
#define debug(...)
#endif

static pid_t child_new(server* s);

static int parse_request(int sockfd) {
    int i;
    int result = 0;
    char buf[4096], *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    ssize_t rret;

    while (1) {
        while ((rret = read(sockfd, buf+buflen, sizeof(buf) - buflen)) == -1
            && errno == EINTR);
        if (rret < 0) {
            perror("read");
            result = -1;
            goto end;
        }

        if (rret == 0) {
            /* EOF? */
            result = -1;
            goto end;
        }

        prevbuflen = buflen;
        buflen += rret;
        /* parse the request */
        num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_request(buf, buflen, (const char **)&method, &method_len, (const char**)&path, &path_len,
            &minor_version, headers, &num_headers, prevbuflen);
        if (pret > 0)
            break; /* successfully parsed the request */
        else if (pret == -1) {
            result = -1;
            goto end;
        }
        /* request is incomplete, continue the loop */
        /*assert(pret == -2);*/
        if (buflen == sizeof(buf)) {
            result = -1;
            goto end;
        }
    }


    printf("request is %d bytes long\n", pret);
    printf("method is %.*s\n", (int)method_len, method);
    printf("path is %.*s\n", (int)path_len, path);
    printf("HTTP version is 1.%d\n", minor_version);
    printf("headers:\n");
    printf("PID: %d", getpid());
    for (i = 0; i != num_headers; ++i) {
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name,
            (int)headers[i].value_len, headers[i].value);
    }
end:
    return result;
}

static int child_run(server* s) {
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    int newsockfd;
    int w_size;
    char * dummy_out = "<html><body><h1>OK</h1></body></html>";

    for(;;) {
        if ((newsockfd = accept(s->sockfd, &addr, &addr_len)) < 0) {
            perror("accept");
            continue;
        }
        parse_request(newsockfd);

        /* DUMMY data */
        w_size = write(newsockfd, dummy_out, strlen(dummy_out));
        if (w_size < 0)
            perror("write");

        close(newsockfd);
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
    if (s->pids)
        free(s->pids);
    free(s);
    return 0;
}

