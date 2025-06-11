#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

void crash_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    fprintf(stderr, "Crash detected! Signal: %d\n", sig);
    fprintf(stderr, "Fault address: %p\n", info->si_addr);
#if defined(__x86_64__)
    fprintf(stderr, "RIP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
#endif
    _exit(1);
}

int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);

    int *p = NULL;
    *p = 123; // triggers SIGSEGV

    return 0;
}