#include <stdio.h>
#include <time.h>
#include <errno.h>

int main() {
    struct timespec req = {1, 0}; // 1 секунда
    while (nanosleep(&req, &req) == -1 && errno == EINTR) {

    }
    puts("Wake up!");
    return 0;
}