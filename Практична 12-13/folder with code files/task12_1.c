#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main() {
    union sigval val;
    val.sival_int = 123;

    pid_t pid = getpid(); 
    sigqueue(pid, SIGRTMIN, val);
    return 0;
}