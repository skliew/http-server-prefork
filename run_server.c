#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#define PORT 9090
#define N_CHILDREN 2

int quit = 0;

void sig_handler(int signo) {
    fprintf(stderr, "Received signal %s\n", strsignal(signo));
    if (signo == SIGINT) {
        quit = 1;
    }
}

int main(void) {
    server* s = server_new(PORT, N_CHILDREN);
    if (NULL == s) {
        fprintf(stderr, "Error allocating new server\n");
        exit(1);
    }

    server_start(s);
    
    if (signal(SIGINT, sig_handler) < 0) {
        perror("signal");
        goto error;
    }

    for(;;) {
        sleep(2);
        if (quit) {
            break;
        }
    }
    server_stop(s);
    server_destroy(s);
    return 0;

error:
    server_destroy(s);
    return 1;
}
