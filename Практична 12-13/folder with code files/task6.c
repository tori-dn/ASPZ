#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

int main() {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;       
    sa.sa_flags = SA_NOCLDWAIT;    
    sigaction(SIGCHLD, &sa, NULL); 

    if (fork() == 0) {
        printf("Child exiting\n");
        _exit(0);
    }

    printf("Parent sleeping\n");
    sleep(3);
    printf("Parent done\n");
    return 0;
}