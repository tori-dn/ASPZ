#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void handler(int sig) {
    const char *msg = "Signal caught\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

int main() {
    struct sigaction sa;

    sa.sa_handler = handler;

    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);

    sa.sa_flags = SA_RESTART | SA_NODEFER;

    sigaction(SIGINT, &sa, NULL);

    printf("Send SIGINT (Ctrl+C) or SIGTERM (kill -TERM <pid>)\n");
    while (1) pause();
}