#task5.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t big_size = (size_t)-1;  

    void *ptr = malloc(1024);  
    if (!ptr) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    printf("Before realloc, ptr = %p\n", ptr);

    ptr = realloc(ptr, big_size); 

    if (!ptr) {
        printf("realloc failed, memory leak occurred!\n");
    } else {
        printf("realloc succeeded, ptr = %p\n", ptr);
        free(ptr);
    }

    return 0;
}

#task5_1.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t big_size = (size_t)-1;

    void *ptr = malloc(1024);
    if (!ptr) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    printf("Before realloc, ptr = %p\n", ptr);

    void *tmp = realloc(ptr, big_size);
    if (!tmp) {
        printf("realloc failed, but old ptr is still valid: %p\n", ptr);
        free(ptr);
    } else {
        ptr = tmp;
        printf("realloc succeeded, ptr = %p\n", ptr);
        free(ptr);
    }

    return 0;
}


