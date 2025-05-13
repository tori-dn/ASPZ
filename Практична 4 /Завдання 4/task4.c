
// тестовий
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = NULL;
    size_t n = 16;

    for (int i = 0; i < 3; ++i) {
        if (!ptr)
            ptr = malloc(n);

        ((char*)ptr)[0] = 'A'; 
        ((char*)ptr)[1] = '\0';
        printf("Iteration %d, ptr = %p, content = %s\n", i, ptr, (char*)ptr);

        free(ptr);  
    }

    return 0;
}

// Правильний варіант:
#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t n = 16;

    for (int i = 0; i < 3; ++i) {
        void *ptr = malloc(n);  

        if (!ptr) {
            fprintf(stderr, "malloc failed\n");
            exit(EXIT_FAILURE);
        }

        ((char*)ptr)[0] = 'A';
        ((char*)ptr)[1] = '\0';

        printf("Iteration %d, ptr = %p, content = %s\n", i, ptr, (char*)ptr);

        free(ptr);  
    }

    return 0;
}

