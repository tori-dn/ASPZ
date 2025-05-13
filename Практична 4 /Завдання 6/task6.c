#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = NULL;
    size_t n = 32;

    ptr = realloc(NULL, n);
    if (ptr) {
        printf("realloc(NULL, %zu) succeeded: %p\n", n, ptr);
        free(ptr);
    } else {
        printf("realloc(NULL, %zu) failed\n", n);
    }

    ptr = malloc(n);
    if (!ptr) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    void *result = realloc(ptr, 0);
    if (result == NULL) {
        printf("realloc(ptr, 0) returned NULL (memory freed)\n");
    } else {
        printf("realloc(ptr, 0) returned non-NULL: %p (still freed)\n", result);
        free(result); 
    }

    void *zero = realloc(NULL, 0);
    if (zero == NULL) {
        printf("realloc(NULL, 0) returned NULL\n");
    } else {
        printf("realloc(NULL, 0) returned non-NULL: %p\n", zero);
        free(zero);
    }

    return 0;
}
