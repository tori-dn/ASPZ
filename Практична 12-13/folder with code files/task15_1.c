#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

int main() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    int sfd = signalfd(-1, &mask, 0);

    printf("Waiting for SIGUSR1 (via signalfd)...\n");

    struct signalfd_siginfo fdsi;
    read(sfd, &fdsi, sizeof(fdsi)); 
    printf("Got signal %d from PID %d\n", fdsi.ssi_signo, fdsi.ssi_pid);
    return 0;
}