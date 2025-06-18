#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void handler(int sig, siginfo_t *si, void *uc) {
    write(STDOUT_FILENO, "Timer fired!\n", 13);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [realtime|monotonic]\n", argv[0]);
        return 1;
    }

    clockid_t clkid;
    if (strcmp(argv[1], "realtime") == 0) {
        clkid = CLOCK_REALTIME;
    } else if (strcmp(argv[1], "monotonic") == 0) {
        clkid = CLOCK_MONOTONIC;
    } else {
        fprintf(stderr, "Unknown clock type.\n");
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGRTMIN, &sa, NULL);

    timer_t timerid;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;

    if (timer_create(clkid, &sev, &timerid) == -1) {
        perror("timer_create");
        return 1;
    }

    struct itimerspec its;
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timerid, 0, &its, NULL) == -1) {
        perror("timer_settime");
        return 1;
    }

    printf("Timer set for 10 seconds using %s clock. Put system to sleep now.\n", argv[1]);
    while (1)
        pause();
}
