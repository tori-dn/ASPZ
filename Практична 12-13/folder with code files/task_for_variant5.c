#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <setjmp.h>

#define NUM_THREADS 2

sigjmp_buf jump_buffers[NUM_THREADS];  
pthread_t threads[NUM_THREADS];
int has_failed[NUM_THREADS] = {0};  // додано флаг для кожного потоку

void segv_handler(int sig, siginfo_t *info, void *ucontext) {
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_equal(threads[i], pthread_self())) {
            printf("[Thread %d] Caught SIGSEGV, recovering...\n", i);
            siglongjmp(jump_buffers[i], 1);
        }
    }
    printf("Unknown thread caught SIGSEGV\n");
    exit(1);
}

void* thread_func(void* arg) {
    int tid = *(int*)arg;
    printf("[Thread %d] Starting...\n", tid);

    if (sigsetjmp(jump_buffers[tid], 1) == 0) {
        printf("[Thread %d] Set checkpoint\n", tid);
    } else {
        printf("[Thread %d] Recovered from segmentation fault!\n", tid);
        has_failed[tid] = 1;
    }

    sleep(1);
    if (tid == 1 && !has_failed[tid]) {
        printf("[Thread %d] Causing segmentation fault...\n", tid);
        int *p = NULL;
        *p = 42;  
    }

    printf("[Thread %d] Finished normally.\n", tid);
    return NULL;
}

int main() {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segv_handler;
    sigaction(SIGSEGV, &sa, NULL);

    int ids[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, thread_func, &ids[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    puts("All threads finished.");
    return 0;
}
