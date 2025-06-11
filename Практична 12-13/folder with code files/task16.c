#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);

    sigprocmask(SIG_BLOCK, &set, NULL);

    printf("Receiver PID: %d\n", getpid());
    printf("Waiting for SIGUSR1 synchronously...\n");

    siginfo_t info;
    sigwaitinfo(&set, &info); 

    printf("Got signal %d from PID %d\n", info.si_signo, info.si_pid);
    return 0;
}