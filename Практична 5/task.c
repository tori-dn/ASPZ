#include <stdio.h>
#include <stdlib.h>

void maybe_free_twice(int *p, int flag) {
    free(p);
    if (flag) {
        free(p);
    }
}

int main() {
    int *ptr = malloc(sizeof(int));
    *ptr = 100;

    maybe_free_twice(ptr, 1); 

    printf("Program has ended.\n");
    return 0;
}
