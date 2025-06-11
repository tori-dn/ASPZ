#include <unistd.h>
#include <signal.h>
#include <string.h>

void handler(int sig) {
    const char *msg = "Received SIGINT\n";
    write(STDOUT_FILENO, msg, strlen(msg));  
}
int main() {
    signal(SIGINT, handler);
    while (1);
}
