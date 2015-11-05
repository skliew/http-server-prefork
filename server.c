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

#define CHECK_BUF_NOT_NULL(X)\
    newbuf = X;\
    if (NULL == newbuf){\
      goto cleanup;\
    } else {\
      buf = newbuf;\
    }

static void convert_header_name(const char* header, size_t size) {
    size_t i = 0;
    char *c = (char *)header;
    while (i < size) {
        if (*c >= 'a' && *c <= 'z')
            *c &= ~0x20;
        else if (*c == '-')
            *c = '_';
        c++; i++;
    }
}

static int http_response_write(int sockfd, const char* status, khash_t(env) *headers, const char* body) {
    int w_size = -1;
    sds buf = sdsempty();
    sds newbuf;
    const char *key, *value;

    CHECK_BUF_NOT_NULL(sdscatprintf(buf, "HTTP/1.1 %s\r\n", status));
    CHECK_BUF_NOT_NULL(sdscat(buf, "Connection: close\r\n"));

    kh_foreach(headers, key, value, {
        CHECK_BUF_NOT_NULL(sdscatprintf(buf, "%s: %s\r\n", key, value));
    });

    CHECK_BUF_NOT_NULL(sdscatprintf(buf, "\r\n%s\r\n", body));
    w_size = write(sockfd, buf, sdslen(buf));
    if (w_size < 0)
        perror("write");

cleanup:
    sdsfree(buf);
    return w_size;
}

static int env_destroy(khash_t(env) *env) {
    const char *key, *value;
    kh_foreach(env, key, value, {
        sdsfree((sds)key);
        sdsfree((sds)value);
    });
    kh_destroy(env, env);
    return 0;
}

static char * env_get(khash_t(env) *env, const char* key) {
    char * result = NULL;
    khint_t k = kh_get(env, env, key);
    if (k != kh_end(env) && kh_exist(env, k)) {
        result = kh_val(env, k);
    }
    return result;
}

#define STR_N_STRLEN(s) s, strlen(s)

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

static size_t find_chr(char * s, size_t len, char c) {
    size_t i;
    for(i = 0; i < len; i++, s++) {
        if (c == *s)
            break;
    }
    return i;
}

static khash_t(env)* parse_request(int sockfd) {
    int i;
    char parser_buf[4096], *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = 0, prevbuflen = 0, method_len, path_len, num_headers;
    ssize_t rret;
    sds header_key, header_value;
    sds buf, newbuf;
    khash_t(env) *env = kh_init(env);
    size_t c;

    debug("sockfd: %d\n", sockfd);

    while (1) {
        debug_syscall("read\n");
        while ((rret = read(sockfd, parser_buf+buflen, sizeof(parser_buf) - buflen)) == -1
            && errno == EINTR);
        debug_syscall("read done\n");

        if (quit) {
            goto cleanup;
        }

        if (rret < 0) {
            perror("read");
            goto cleanup;
        }

        if (rret == 0) {
            /* EOF? */
            goto cleanup;
        }

        prevbuflen = buflen;
        buflen += rret;
        /* parse the request */
        num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_request(parser_buf, buflen, (const char **)&method, &method_len, (const char**)&path, &path_len,
            &minor_version, headers, &num_headers, prevbuflen);
        if (pret > 0)
            break; /* successfully parsed the request */
        else if (pret == -1) {
            goto cleanup;
        }
        /* request is incomplete, continue the loop */
        /*assert(pret == -2);*/
        if (buflen == sizeof(parser_buf)) {
            goto cleanup;
        }
    }

    c = find_chr(path, path_len, '?');
    if (c != path_len) {
        c++;
        const char * query_string = path + c;
        if (env_put(env, STR_N_STRLEN("QUERY_STRING"), query_string, path_len - c) < 0) goto cleanup;
    }

    if (env_put(env, STR_N_STRLEN("REQUEST_METHOD"), method, method_len) < 0) goto cleanup;
    if (env_put(env, STR_N_STRLEN("PATH_INFO"), path, path_len) < 0) goto cleanup;
    if (env_put(env, STR_N_STRLEN("crack.input"), (char *)&sockfd, sizeof(sockfd)) < 0) goto cleanup;
    for (i = 0; i != num_headers; ++i) {
        buf = newbuf = NULL;
        buf = sdsnew("HTTP_");
        /* convert headers in place */
        convert_header_name(headers[i].name, headers[i].name_len);
        CHECK_BUF_NOT_NULL(sdscatlen(buf, headers[i].name, headers[i].name_len));
        header_key = buf;
        CHECK_BUF_NOT_NULL(sdsnewlen(headers[i].value, headers[i].value_len));
        header_value = buf;
        if (env_put(env, header_key, sdslen(header_key), header_value, sdslen(header_value)) < 0) {
            fprintf(stderr, "[Warning] error populating headers\n");
        }
        sdsfree(header_key);
        sdsfree(header_value);
    }
    return env;
cleanup:
    if (env) {
        env_destroy(env);
    }
    if (buf)
        sdsfree(buf);
    if (newbuf)
        sdsfree(newbuf);
    return NULL;
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
    const char *key, *value;
    khash_t(env) *dummy_response_headers;
    khash_t(env) *env = NULL;

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
        env = parse_request(newsockfd);
        if (!env) {
            fprintf(stderr, "Parse error\n");
            continue;
        }
        {
            int * sfd = (int*) env_get(env, "crack.input");
            debug("Getting crack.input: %d\n", *sfd);
        }

        dummy_response_headers = kh_init(env);
        env_put(dummy_response_headers, "Content-Type", strlen("Content-Type"), "text/plain", strlen("text/plain"));
        http_response_write(
            newsockfd,
            "200",
            dummy_response_headers,
            "OK"
        );
        env_destroy(dummy_response_headers);
        kh_foreach(env, key, value, {
            debug_http("%s: %s\n", key, value);
        });
        env_destroy(env);

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

