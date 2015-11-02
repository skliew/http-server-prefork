#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>

#include "server.h"
#include "picohttpparser/picohttpparser.h"
#include "sds/sds.h"
#include "khash.h"

#define BACKLOG 20
#define DEBUG 1
#define DEBUG_HTTP 1
#define DEBUG_SYSCALL 0

#if DEBUG
#define debug(...) fprintf(stdout, __VA_ARGS__)
#else
#define debug(...)
#endif

#if DEBUG_HTTP
#define debug_http(...) fprintf(stdout, __VA_ARGS__)
#else
#define debug_http(...)
#endif

#if DEBUG_SYSCALL
#define debug_syscall(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_syscall(...)
#endif

static pid_t child_new(server* s);
static int quit = 0;

KHASH_MAP_INIT_STR(env, char*)

static int http_response_write(int sockfd, const char* status, khash_t(env) *headers, const char* body) {
    int w_size;
    /* TODO dummy for now */
    char * dummy_string = "HTTP/1.1 200\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nOK\r\n";

    w_size = write(sockfd, dummy_string, strlen(dummy_string));
    if (w_size < 0)
        perror("write");

    return w_size;
}

static int env_destroy(khash_t(env) *env) {
    const char *key, *value;
    kh_foreach(env, key, value, {
        sdsfree((void*)key);
        sdsfree((void*)value);
    });
    kh_destroy(env, env);
    return 0;
}

static int env_put(khash_t(env) *env, const char* k, int klen, const char* v, int vlen) {
    sds key, value;
    int ret;
    khint_t iter;

    key = sdsnewlen(k, klen);
    value = sdsnewlen(v, vlen);

    if (NULL == key || NULL == value) {
        if (key) {
            sdsfree(key);
        }
        if (value) {
            sdsfree(value);
        }
        return -1;
    }

    iter = kh_put(env, env, key, &ret);
    if (ret < 0) {
        sdsfree(key);
        sdsfree(value);
        return ret;
    }
    kh_value(env, iter) = value;
    return ret;
}

static int parse_request(int sockfd) {
    int i;
    int result = 0;
    char buf[4096], *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    ssize_t rret;
    khash_t(env) *env = kh_init(env);

    while (1) {
        debug_syscall("read\n");
        while ((rret = read(sockfd, buf+buflen, sizeof(buf) - buflen)) == -1
            && errno == EINTR);
        debug_syscall("read done\n");

        if (quit) {
            goto end;
        }

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

    debug_http("request is %d bytes long\n", pret);
    debug_http("method is %.*s\n", (int)method_len, method);
    debug_http("path is %.*s\n", (int)path_len, path);
    debug_http("HTTP version is 1.%d\n", minor_version);
    debug_http("headers:\n");
    for (i = 0; i != num_headers; ++i) {
        if (env_put(env, headers[i].name, headers[i].name_len,
              headers[i].value, headers[i].value_len) < 0) {
            continue;
        }
    }
    {
        const char *key, *value;
        kh_foreach(env, key, value, {
            debug_http("%s:%s\n", key, value);
            sdsfree((void*)key);
            sdsfree((void*)value);
        });
        kh_destroy(env, env);
    }
end:
    return result;
}

static void sig_handler(int signo) {
    fprintf(stderr, "Received signal %s in child %d\n", strsignal(signo), getpid());
    if (signo == SIGINT) {
    } else if (signo == SIGTERM) {
        quit = 1;
    }
}

static int child_run(server* s) {
    struct sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    int newsockfd;
    struct sigaction action;
    khash_t(env) *dummy_response_headers;

    memset(&action, 0, sizeof(action));
    action.sa_handler = sig_handler;
    if (sigaction(SIGTERM, &action, NULL) < 0) {
        perror("signal");
        /* Do what? */
    }
    if (sigaction(SIGINT, &action, NULL) < 0) {
        perror("signal");
        /* Do what? */
    }

    for(;;) {
        if (quit) {
            return 0;
        }
        debug_syscall("accept\n");
        if ((newsockfd = accept(s->sockfd, &addr, &addr_len)) < 0) {
            perror("accept");
            continue;
        }
        debug_syscall("accept done\n");
        parse_request(newsockfd);

        dummy_response_headers = kh_init(env);
        env_put(dummy_response_headers, "Content-Type", strlen("Content-Type"), "text/plain", strlen("text/plain"));
        http_response_write(
            newsockfd,
            "200",
            dummy_response_headers,
            "OK"
        );
        env_destroy(dummy_response_headers);

        close(newsockfd);
    }
    return 0;
}

static pid_t child_new(server* s) {
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        child_run(s);
        server_destroy(s);
        exit(0);
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
    int option = 1;

    if (NULL == s)
        perror("malloc");

    s->n_children = n_children;

    if (s->n_children) {
        if ((s->pids = (pid_t*)malloc(n_children * sizeof(pid_t))) == NULL) {
            perror("malloc pids");
            free(s);
            return NULL;
        }

        memset(s->pids, 0, n_children*sizeof(pid_t));
    }

    if ((s->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    if (setsockopt(s->sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        perror("setsockopt");
    }

    if (setsockopt(s->sockfd, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(option)) < 0) {
        perror("setsockopt");
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
    int n_children = 0;
    int status;

    for (i = 0; i < s->n_children; i++) {
        if (s->pids[i] == 0) {
            continue;
        }
        debug("Killing PID %d\n", s->pids[i]);
        n_children++;
        int ret = kill(s->pids[i], SIGTERM);
        if (ret < 0)
            perror("kill");
    }

    if (!n_children)
        return 0;

    while (n_children) {
        debug("Waiting %d [%d]\n", n_children, getpid());
        pid_t res = wait(&status);
        if (res < 0) {
            perror("wait");
            continue;
        }
        n_children--;
    }

    return 0;
}

int server_destroy(server* s) {
    close(s->sockfd);
    if (s->pids) {
        free(s->pids);
        s->pids = NULL;
    }
    free(s);
    debug("Destroy... [%d]\n", getpid());
    return 0;
}

