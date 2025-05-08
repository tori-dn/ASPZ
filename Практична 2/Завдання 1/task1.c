#include <stdio.h>
#include <time.h>
#include <limits.h>

int main() {
    time_t max_time = (time_t)~((time_t)1 << (sizeof (time_t) * 8 - 1));
    printf ("Max time_t value: %ld\n", (long)max_time);
    printf ("Date and time: %s", ctime(&max_time));
    time_t overf low_time = max_time + 1;
    printf ("After overf low: %s", ctime(&overflow_time) );

    return 0;
}
