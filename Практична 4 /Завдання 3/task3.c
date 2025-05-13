#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(0);
    if (ptr == NULL) {
        printf("malloc(0) returned NULL\n");
    } else {
        printf("malloc(0) returned non-NULL pointer: %p\n", ptr);
        free(ptr);
    }
    return 0;
}
