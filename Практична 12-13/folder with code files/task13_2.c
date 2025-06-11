#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    union sigval val;
    val.sival_int = 777; // Передаємо ціле число

    sigqueue(pid, SIGUSR1, val);

    return 0;
}