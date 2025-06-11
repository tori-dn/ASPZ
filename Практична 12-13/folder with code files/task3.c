#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);

    sigprocmask(SIG_BLOCK, &set, NULL);
    printf("SIGINT blocked. Try pressing Ctrl+C now (nothing will happen)...\n");
    sleep(10);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("SIGINT unblocked. Now press Ctrl+C to exit.\n");

    while (1) {
        sleep(1);
    }

    return 0;
}
