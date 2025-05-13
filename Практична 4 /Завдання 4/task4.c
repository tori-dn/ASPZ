#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = NULL;
    size_t n = 16;

    for (int i = 0; i < 3; ++i) {
        if (!ptr)
            ptr = malloc(n);

        if (!ptr) {
            fprintf(stderr, "malloc failed\n");
            exit(EXIT_FAILURE);
        }

        printf("Iteration %d, ptr = %p\n", i, ptr);
        ((char*)ptr)[0] = 'A'; 
        ((char*)ptr)[1] = '\0';
        printf("ptr content: %s\n", (char*)ptr);

        free(ptr);
        ptr = NULL; 
    }

    return 0;
}
