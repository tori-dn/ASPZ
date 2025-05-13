#task2_1.c
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

int main() {
    int xa = 1000000;
    int xb = 1000000;
    int num = xa * xb;
    printf("num = %d (undefined behavior due to overflow)\n", num);

    size_t size = num; 
    printf("Pass a malloc(%zu)\n", size); 

    void *ptr = malloc(size);
    if (ptr == NULL) {
        perror("malloc failed");
    } else {
        printf("Allocated %d bytes\n", num);
        free(ptr);
    }

    return 0;
}

#task2_2.c
#include <stdlib.h>
#include <stdio.h>

int main() {
    int negative_size = -1;
    size_t size = negative_size; 

    printf("Pass a malloc(%zu)\n", size); 

    void *ptr = malloc(size);
    if (ptr == NULL) {
        perror("malloc failed");
    } else {
        printf("Allocated %zu bytes\n", size);
        free(ptr);
    }

    return 0;
}
