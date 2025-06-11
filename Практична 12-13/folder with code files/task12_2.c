#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

void handler(int sig, siginfo_t *info, void *ctx) {
    printf("Received RT signal %d with data: %d\n", sig, info->si_value.sival_int);
}

int main() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO; 
    sa.sa_sigaction = handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGRTMIN, &sa, NULL);

    pause(); 
    return 0;
}