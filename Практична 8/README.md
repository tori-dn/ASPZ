# Завдання 8.1
Умова: Чи може виклик `count = write(fd, buffer, nbytes);` повернути в змінній count значення, відмінне від `nbytes`? Якщо так, то чому? Наведіть робочий приклад програми, яка демонструє вашу відповідь.

---
### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int main() {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    int flags = fcntl(pipefd[1], F_GETFL);
    fcntl(pipefd[1], F_SETFL, flags | O_NONBLOCK);

    const size_t buf_size = 65536;
    char *buffer = malloc(buf_size);
    memset(buffer, 'A', buf_size);

    ssize_t count = write(pipefd[1], buffer, buf_size);
    if (count == -1) {
        perror("write");
    } else if ((size_t)count < buf_size) {
        printf("write() wrote only %zd bytes з %zu\n", count, buf_size);
    } else {
        printf("write() successfully wrote all %zd bytes\n", count);
    }

    free(buffer);
    close(pipefd[0]);
    close(pipefd[1]);

    return 0;
}
```
---

### Пояснення програми:
Так, виклик `write(fd, buffer, nbytes)` може повернути значення, відмінне від `nbytes`, і це не обов’язково є помилкою.

### Чому так може статися?
- Операція write() може записати менше байтів, ніж запрошено, у таких випадках:
  
- Файловий дескриптор вказує на неперехоплювальний ресурс, наприклад, неблокуючий сокет або FIFO, і в буфері прийому обмежений простір.

- Сигнал перериває виконання write() до завершення (і частина байтів вже записана).

- Обмеження ядра (наприклад, максимальний розмір блоку для певного типу файлової системи чи пристрою).

- Неповне заповнення буфера, наприклад, якщо пишемо у pipe або термінал.


---

### Результат роботи
![task1](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%208/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%201/task1.png)

---

# Завдання 8.2
Умова: Є файл, дескриптор якого — fd. Файл містить таку послідовність байтів: 4, 5, 2, 2, 3, 3, 7, 9, 1, 5. У програмі виконується наступна послідовність системних викликів:
lseek(fd, 3, SEEK_SET);
read(fd, &buffer, 4);
де виклик lseek переміщує покажчик на третій байт файлу. Що буде містити буфер після завершення виклику read? Наведіть робочий приклад програми, яка демонструє вашу відповідь.

---
### Код програми:
```
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    int fd = open("testfile", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    off_t offset = 3;
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("lseek");
        close(fd);
        exit(EXIT_FAILURE);
    }

    char buffer[4];
    ssize_t bytesRead = read(fd, buffer, 4);
    if (bytesRead == -1) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Read bytes: ");
    for (ssize_t i = 0; i < bytesRead; i++) {
        printf("%d ", buffer[i]);
    }
    printf("\n");

    close(fd);
    return 0;
}

```
---

### Пояснення програми:
Програма відкриває файл у режимі тільки для читання, переміщує покажчик на третій байт файлу за допомогою `lseek(fd, 3, SEEK_SET)`, після чого читає 4 байти з поточної позиції за допомогою `read(fd, buffer, 4)`. Прочитані байти зберігаються у масиві `buffer`, і програма виводить їх на екран. Наприкінці файл закривається.

---

### Результат роботи
![task2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%208/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2.png)

---

# Завдання 8.3
Умова: Бібліотечна функція qsort призначена для сортування даних будь-якого типу. Для її роботи необхідно підготувати функцію порівняння, яка викликається з qsort кожного разу, коли потрібно порівняти два значення.
Оскільки значення можуть мати будь-який тип, у функцію порівняння передаються два вказівники типу void* на елементи, що порівнюються.
Напишіть програму, яка досліджує, які вхідні дані є найгіршими для алгоритму швидкого сортування. Спробуйте знайти кілька масивів даних, які змушують qsort працювати якнайповільніше. Автоматизуйте процес експериментування так, щоб підбір і аналіз вхідних даних виконувалися самостійно.

Придумайте і реалізуйте набір тестів для перевірки правильності функції qsort.

---
### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_SIZE 10000

int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

void generate_random_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = rand() % 10000;
    }
}

void generate_sorted_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = i;
    }
}

void generate_reverse_sorted_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = size - i - 1;
    }
}

void generate_uniform_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = 5;  
    }
}

void measure_sort_time(void (*data_generator)(int*, size_t), int *arr, size_t size) {
    data_generator(arr, size);
    
    clock_t start = clock();
    qsort(arr, size, sizeof(int), compare);
    clock_t end = clock();
    
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time taken: %f seconds\n", time_taken);
}

int main() {
    int arr[MAX_SIZE];
    
    srand(time(NULL));

    printf("Sorted array:\n");
    measure_sort_time(generate_sorted_data, arr, MAX_SIZE);
    
    printf("\nReverse sorted array:\n");
    measure_sort_time(generate_reverse_sorted_data, arr, MAX_SIZE);
    
    printf("\nRandom array:\n");
    measure_sort_time(generate_random_data, arr, MAX_SIZE);
    
    printf("\nUniform array:\n");
    measure_sort_time(generate_uniform_data, arr, MAX_SIZE);
    
    return 0;
}
```
---
### Тести:
```
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_SIZE 10000

int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

void generate_random_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = rand() % 10000;
    }
}

void generate_sorted_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = i;
    }
}

void generate_reverse_sorted_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = size - i - 1;
    }
}

void generate_uniform_data(int *arr, size_t size) {
    for (size_t i = 0; i < size; i++) {
        arr[i] = 5;  // Всі елементи однакові
    }
}

void measure_sort_time(void (*data_generator)(int*, size_t), int *arr, size_t size) {
    data_generator(arr, size);
    
    clock_t start = clock();
    qsort(arr, size, sizeof(int), compare);
    clock_t end = clock();
    
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time taken: %f seconds\n", time_taken);
}


void test_sorted_array() {
    int arr[] = {1, 2, 3, 4, 5};
    size_t size = sizeof(arr) / sizeof(arr[0]);
    qsort(arr, size, sizeof(int), compare);
    for (size_t i = 1; i < size; i++) {
        if (arr[i-1] > arr[i]) {
            printf("Test failed: sorted array not sorted!\n");
            return;
        }
    }
    printf("Test passed: sorted array is correctly sorted.\n");
}

void test_reverse_sorted_array() {
    int arr[] = {5, 4, 3, 2, 1};
    size_t size = sizeof(arr) / sizeof(arr[0]);
    qsort(arr, size, sizeof(int), compare);
    for (size_t i = 1; i < size; i++) {
        if (arr[i-1] > arr[i]) {
            printf("Test failed: reverse sorted array not sorted!\n");
            return;
        }
    }
    printf("Test passed: reverse sorted array is correctly sorted.\n");
}

void test_uniform_array() {
    int arr[] = {5, 5, 5, 5, 5};
    size_t size = sizeof(arr) / sizeof(arr[0]);
    qsort(arr, size, sizeof(int), compare);
    for (size_t i = 1; i < size; i++) {
        if (arr[i-1] != arr[i]) {
            printf("Test failed: uniform array not sorted!\n");
            return;
        }
    }
    printf("Test passed: uniform array is correctly sorted.\n");
}

void test_random_array() {
    int arr[5] = {3, 1, 4, 5, 2};
    size_t size = sizeof(arr) / sizeof(arr[0]);
    qsort(arr, size, sizeof(int), compare);
    for (size_t i = 1; i < size; i++) {
        if (arr[i-1] > arr[i]) {
            printf("Test failed: random array not sorted!\n");
            return;
        }
    }
    printf("Test passed: random array is correctly sorted.\n");
}

void test_empty_array() {
    int arr[] = {};
    size_t size = sizeof(arr) / sizeof(arr[0]);
    qsort(arr, size, sizeof(int), compare);
    printf("Test passed: empty array handled correctly.\n");
}

void test_single_element_array() {
    int arr[] = {5};
    size_t size = sizeof(arr) / sizeof(arr[0]);
    qsort(arr, size, sizeof(int), compare);
    if (arr[0] != 5) {
        printf("Test failed: single element array not sorted correctly!\n");
    } else {
        printf("Test passed: single element array is correctly handled.\n");
    }
}

void test_large_array() {
    int arr[MAX_SIZE];
    size_t size = MAX_SIZE;
    generate_random_data(arr, size);
    
    clock_t start = clock();
    qsort(arr, size, sizeof(int), compare);
    clock_t end = clock();
    
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Test passed: large array sorted in %f seconds.\n", time_taken);
}

int main() {
    test_sorted_array();
    test_reverse_sorted_array();
    test_uniform_array();
    test_random_array();
    test_empty_array();
    test_single_element_array();
    test_large_array();

    return 0;
}

```
---

### Опис тестів:
`Тест з відсортованим масивом`: Перевіряє правильність сортування вже відсортованого масиву. Масив має залишатися незмінним після сортування.

`Тест з зворотно відсортованим масивом`: Перевіряє, чи правильно сортується масив, елементи якого йдуть у зворотному порядку.

`Тест з масивом однакових значень`: Перевіряє, чи працює сортування для масиву, де всі елементи однакові. Масив не змінюється після сортування.

`Тест з випадковим масивом`: Перевіряє, чи правильно працює алгоритм сортування для випадкових значень у масиві.

`Тест з порожнім масивом`: Перевіряє, чи коректно обробляється порожній масив без помилок.

`Тест з одним елементом`: Перевіряє правильність роботи сортування для масиву, що містить лише один елемент.

`Тест з великим масивом`: Перевіряє продуктивність алгоритму на великому масиві (10,000 елементів).

### Пояснення програми:
Основна програма складається з набору тестів для перевірки функціональності бібліотечної функції `qsort`. Для кожного тесту програма генерує відповідний масив (відсортований, зворотно відсортований, з однаковими елементами тощо) і викликає функцію `qsort` для сортування масиву. Після сортування перевіряється, чи правильно відсортовані елементи масиву. Якщо умови тесту виконуються (масив правильно відсортований), виводиться повідомлення про успішне проходження тесту. Також є тест для вимірювання часу сортування великого масиву, що дозволяє оцінити продуктивність алгоритму на великих обсягах даних.

---

### Результат роботи
![task3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%208/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3.png)

### Результат виконання тестів
![task3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%208/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/tests_task3.png)

---

# Завдання 8.4
Умова: Виконайте наступну програму на мові програмування С:
```
int main() {
  int pid;
  pid = fork();
  printf("%d\n", pid);
}
```
Завершіть цю програму. Припускаючи, що виклик fork() був успішним, яким може бути результат виконання цієї програми?

---
### Код програми:
```
#include <stdio.h>
#include <unistd.h>

int main() {
    int pid;
    pid = fork();

    printf("pid = %d\n", pid);
    return 0;
}

```
---

### Пояснення програми:
Програма викликає `fork()`, щоб створити новий процес. Після виклику існує два процеси: батьківський і дочірній. У батьківському процесі `fork()` повертає `PID` дочірнього процесу (додатне число), а в дочірньому — `0`. Обидва процеси виконують команду `printf`, тому програма виводить два рядки з різними значеннями змінної `pid`: один з `0` (у дочірньому процесі), інший з `PID` (у батьківському). Порядок виводу не визначений, оскільки процеси працюють паралельно.

---

### Результат роботи
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%208/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4.png)

---

# Завдання за варіантом 5
Умова: Напишіть програму, яка симулює збій у середині операції `write()` і спробуйте зберегти цілісність даних.


---
### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define DATA "IMPORTANT DATA\n"
#define TEMP_FILE "data.tmp"
#define FINAL_FILE "data.txt"

int main() {
    int fd = open(TEMP_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open temp");
        return 1;
    }

    ssize_t written = write(fd, DATA, strlen(DATA) / 2); 
    if (written < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    printf("Failed after partial write!.\n");
    close(fd);

    fd = open(TEMP_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("reopen temp");
        return 1;
    }

    written = write(fd, DATA, strlen(DATA));
    if (written != strlen(DATA)) {
        perror("full write");
        close(fd);
        return 1;
    }

    close(fd);

    if (rename(TEMP_FILE, FINAL_FILE) != 0) {
        perror("rename");
        return 1;
    }

    printf("data successfully recovered and saved in %s\n", FINAL_FILE);
    return 0;
}
```
---

### Пояснення програми:
Програма спочатку створює тимчасовий файл `data.tmp` і частково записує в нього дані, імітуючи збій. Потім файл перезаписується повністю, і після успішного завершення запису викликається rename(), яка атомарно перейменовує `data.tmp` у `data.txt`. Якщо файл `data.txt` не існує, він буде створений автоматично, а якщо існує — буде замінений. У результаті в `data.txt` гарантовано опиняться повні, цілісні дані `"IMPORTANT DATA\n"`, навіть якщо на попередньому етапі стався збій.

---

### Результат роботи
![task5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%208/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%B0%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5.png)

---

