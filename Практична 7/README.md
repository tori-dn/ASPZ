# Завдання 1
---
Умова: Використайте popen(), щоб передати вивід команди rwho (команда UNIX) до more (команда UNIX) у програмі на C.

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *rwho_fp;
    FILE *more_fp;
    char buffer[1024];

    rwho_fp = popen("rwho", "r");
    if (rwho_fp == NULL) {
        perror("popen rwho");
        exit(EXIT_FAILURE);
    }

    more_fp = popen("more", "w");
    if (more_fp == NULL) {
        perror("popen more");
        pclose(rwho_fp);
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, sizeof(buffer), rwho_fp) != NULL) {
        fputs(buffer, more_fp);
    }

    pclose(rwho_fp);
    pclose(more_fp);

    return 0;
}

```

---

### Пояснення програми:
Програма відкриває два потоки за допомогою `popen()` — один для читання виводу команди `rwho`, інший для запису у команду `more`. Вона читає кожен рядок з `rwho` і передає його в `more` для посторінкового перегляду. Якщо `rwho` не виводить жодних даних (через відсутність активної служби rwhod), more отримує пустий ввід і одразу завершується, показуючи лише ``--More--(END).``

---

### Результат роботи
![task1](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%201/task1.png)

---

# Завдання 2
---
Умова: Напишіть програму мовою C, яка імітує команду ls -l в UNIX — виводить список усіх файлів у поточному каталозі та перелічує права доступу тощо.
 (Варіант вирішення, що просто виконує ls -l із вашої програми, — не підходить.)

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

void print_permissions(mode_t mode) {
    char perms[11] = "----------";

    if (S_ISDIR(mode))  perms[0] = 'd';
    if (S_ISLNK(mode))  perms[0] = 'l';
    if (S_ISCHR(mode))  perms[0] = 'c';
    if (S_ISBLK(mode))  perms[0] = 'b';
    if (S_ISFIFO(mode)) perms[0] = 'p';
    if (S_ISSOCK(mode)) perms[0] = 's';

    if (mode & S_IRUSR) perms[1] = 'r';
    if (mode & S_IWUSR) perms[2] = 'w';
    if (mode & S_IXUSR) perms[3] = 'x';
    if (mode & S_IRGRP) perms[4] = 'r';
    if (mode & S_IWGRP) perms[5] = 'w';
    if (mode & S_IXGRP) perms[6] = 'x';
    if (mode & S_IROTH) perms[7] = 'r';
    if (mode & S_IWOTH) perms[8] = 'w';
    if (mode & S_IXOTH) perms[9] = 'x';

    printf("%s", perms);
}

int main() {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char timebuf[80];
    char symlink_target[1024];

    dir = opendir(".");
    if (dir == NULL) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if (stat(entry->d_name, &file_stat) == -1) {
            perror("stat");
            continue;
        }

        print_permissions(file_stat.st_mode);
        printf(" ");
        printf("%2ld ", (long) file_stat.st_nlink);

        struct passwd *pw = getpwuid(file_stat.st_uid);
        printf("%s ", pw ? pw->pw_name : "unknown");

        struct group *gr = getgrgid(file_stat.st_gid);
        printf("%s ", gr ? gr->gr_name : "unknown");

        printf("%6ld ", (long) file_stat.st_size);

        struct tm *tm_info = localtime(&file_stat.st_mtime);
        strftime(timebuf, sizeof(timebuf), "%b %d %H:%M", tm_info);
        printf("%s ", timebuf);

        if (S_ISLNK(file_stat.st_mode)) {
            ssize_t len = readlink(entry->d_name, symlink_target, sizeof(symlink_target) - 1);
            if (len != -1) {
                symlink_target[len] = '\0';
                printf("%s -> %s", entry->d_name, symlink_target);
            } else {
                perror("readlink");
            }
        } else {
            printf("%s", entry->d_name);
        }

        printf("\n");
    }

    closedir(dir);
    return 0;
}
```

---

### Пояснення програми:
Ця програма на `C` імітує команду `ls -l`, виводячи детальну інформацію про файли та каталоги в поточному каталозі, включаючи права доступу, кількість жорстких посилань, власника, групу, розмір, час останньої модифікації та ім'я файлу. Якщо файл є символьним посиланням, програма також виводить шлях, на який воно вказує. Для кожного файлу використовується функція `stat()` для отримання метаданих, а для символьних лінків — `readlink()` для визначення їх цілі.

---

### Результат роботи
![task2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2.png)

---

# Завдання 3
---
Умова: Напишіть програму, яка друкує рядки з файлу, що містять слово, передане як аргумент програми (проста версія утиліти grep в UNIX).

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <word> <filename>\n", argv[0]);
        return 1;
    }

    char *word = argv[1];
    char *filename = argv[2];
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, word)) {
            printf("%s", line);
        }
    }

    fclose(file);
    return 0;
}
```
### Вміст file.txt
```
Hello world
This is a simple test file
We are testing the grep_sim program
Another test with more content
No match here
test at the end of line
```

---

### Пояснення програми:
Ця програма на C реалізує просту версію утиліти `grep`, яка шукає вказане слово в кожному рядку файлу, переданого як аргумент, та виводить усі рядки, що містять це слово. Програма відкриває файл для читання, зчитує його рядок за рядком, перевіряє, чи містить кожен рядок задане слово за допомогою функції `strstr()`, і виводить знайдені рядки на екран. Якщо файл не можна відкрити або кількість аргументів неправильна, програма виводить повідомлення про помилку.

---

### Результат роботи
![task3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3.png)

---
# Завдання 4
---
Умова: Напишіть програму, яка виводить список файлів, заданих у вигляді аргументів, з зупинкою кожні 20 рядків, доки не буде натиснута клавіша (спрощена версія утиліти more в UNIX).

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>

#define LINES_PER_PAGE 20

void display_file(FILE *file) {
    char line[1024];
    int line_count = 0;

    while (fgets(line, sizeof(line), file)) {
        printf("%s", line);
        line_count++;

        if (line_count >= LINES_PER_PAGE) {
            printf("\nPress any key to continue...");
            getchar(); 
            line_count = 0;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file1> <file2> ...\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        FILE *file = fopen(argv[i], "r");
        if (file == NULL) {
            perror("Error opening file");
            continue;
        }

        printf("Displaying file: %s\n", argv[i]);
        display_file(file);
        fclose(file);
    }

    return 0;
}
```

---

### Пояснення програми:
Програма по черзі відкриває файли, що передані як аргументи, і виводить їх вміст на екран. Кожні 20 рядків програма зупиняється і чекає на натискання клавіші для продовження. Це дозволяє користувачу переглядати файли частинами, схоже на утиліту more в UNIX.

---

### Результат роботи
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4.png)

---
# Завдання 5
---
Умова: Напишіть програму, яка перелічує всі файли в поточному каталозі та всі файли в підкаталогах.

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

void list_files(const char *path) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    struct stat file_stat;
    char full_path[1024];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (stat(full_path, &file_stat) == -1) {
            perror("stat");
            continue;
        }

        if (S_ISDIR(file_stat.st_mode)) {
            printf("Directory: %s\n", full_path);
            list_files(full_path);  
        } else {
            printf("File: %s\n", full_path);
        }
    }

    closedir(dir);
}

int main() {
    list_files("."); 
    return 0;
}
```

### Вміст текстових файлів:
file1.txt
```
Hello, this is file1.txt.
It contains some text for testing.
AA
BB
C
DD
EE
FF
GG
HH
JJ
KK
LL
MM
NN
OO
PP
QQ
RR
SS
TT
UU
```
file2.txt
```
file2.txt is another example.
It has a few more lines.
Testing file handling in C.
```
subdir/file3.txt
```
This is file3.txt located in a subdirectory.
The subdirectory is part of the test.
You can see how recursion works.

```
---

### Пояснення програми:
Програма спочатку виводить список файлів у поточному каталозі, а потім рекурсивно проходить через всі підкаталоги, виводячи файли та каталоги з кожного з них.

---

### Результат роботи
![task5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%205/task5.png)

---

# Завдання 6
---
Умова: Напишіть програму, яка перелічує лише підкаталоги у алфавітному порядку.

### Код програми:
---
```
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

int compare(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

void list_subdirectories(const char *path) {
    DIR *dir = opendir(path);
    if (dir == NULL) return;

    struct dirent *entry;
    struct stat st;
    char **subdirs = malloc(1024 * sizeof(char *));
    int count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            subdirs[count++] = strdup(entry->d_name);
        }
    }

    closedir(dir);

    qsort(subdirs, count, sizeof(char *), compare);

    for (int i = 0; i < count; i++) {
        printf("Directory: %s/%s\n", path, subdirs[i]);
        free(subdirs[i]);
    }

    free(subdirs);
}

int main() {
    list_subdirectories(".");
    return 0;
}
```

### Вміст текстових файлів:
subdir/file3.txt
```
This is file3.txt located in a subdirectory.
The subdirectory is part of the test.
You can see how recursion works.
Great progress!
```
subdir2/file4.txt
```
This is file4.txt in subdir2.
It is another test file.
The content is simple for testing purposes.
Let's make sure it works with the program.
```
---

### Пояснення програми:
Програма відкриває поточний каталог і зчитує всі його елементи. Вона фільтрує лише ті, які є підкаталогами (ігноруючи . і ..), і додає їхні імена в масив. Потім цей масив сортується в алфавітному порядку за допомогою `qsort`, і на завершення програма виводить список знайдених підкаталогів у форматі `Directory: ./<назва>`

---

### Результат роботи
![task6](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%206/task6.png)

---

# Завдання 7
---
Умова: Напишіть програму, яка показує користувачу всі його/її вихідні програми на C, а потім в інтерактивному режимі запитує, чи потрібно надати іншим дозвіл на читання `(read permission)`; у разі ствердної відповіді — такий дозвіл повинен бути наданий.

---
### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int is_executable(const struct stat *st) {
    return S_ISREG(st->st_mode) && (st->st_mode & S_IXUSR);
}

int main() {
    DIR *dir = opendir(".");
    if (!dir) return 1;

    struct dirent *entry;
    struct stat st;
    char answer[10];

    while ((entry = readdir(dir)) != NULL) {
        if (stat(entry->d_name, &st) == -1) continue;
        if (!is_executable(&st)) continue;

        printf("Executable: %s\n", entry->d_name);
        printf("Grant read permission to others? (y/n): ");
        if (!fgets(answer, sizeof(answer), stdin)) break;
        if (answer[0] == 'y' || answer[0] == 'Y') {
            chmod(entry->d_name, st.st_mode | S_IROTH);
            printf("Read permission granted.\n");
        }
    }

    closedir(dir);
    return 0;
}
```

---

### Пояснення програми:
Програма переглядає всі файли в поточному каталозі, знаходить ті, які є звичайними файлами з дозволом на виконання (вважаються вихідними програмами C), і по черзі запитує користувача, чи надати іншим користувачам дозвіл на читання. Якщо користувач погоджується, програма додає відповідний дозвіл до файлу за допомогою `chmod`

---

### Результат роботи
![task7](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%207/task7.png)

---

# Завдання 8
---
Умова: Напишіть програму, яка надає користувачу можливість видалити будь-який або всі файли у поточному робочому каталозі. Має з’являтися ім’я файлу з запитом, чи слід його видалити.


---
### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main() {
    DIR *dir = opendir(".");
    if (!dir) return 1;

    struct dirent *entry;
    struct stat st;
    char answer[10];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (stat(entry->d_name, &st) == -1) continue;
        if (!S_ISREG(st.st_mode)) continue;

        printf("Delete file %s? (y/n): ", entry->d_name);
        if (!fgets(answer, sizeof(answer), stdin)) break;
        if (answer[0] == 'y' || answer[0] == 'Y') {
            if (remove(entry->d_name) == 0) {
                printf("Deleted.\n");
            } else {
                perror("Error deleting file");
            }
        }
    }

    closedir(dir);
    return 0;
}

```

---

### Пояснення програми:
Програма переглядає всі звичайні файли в поточному каталозі, виводить їх назви та запитує користувача, чи потрібно видалити кожен із них. Якщо користувач вводить y, файл видаляється функцією `remove()`, і про це повідомляється. Спеціальні файли (., ..) і каталоги ігноруються.

---

### Результат роботи
![task8](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%208/task8.png)

---

# Завдання 9
---
Умова: Напишіть програму на C, яка вимірює час виконання фрагмента коду в мілісекундах.


---
### Код програми:
```
#include <stdio.h>
#include <sys/time.h>

int main() {
    struct timeval start, end;
    gettimeofday(&start, NULL);

    volatile long sum = 0;
    for (long i = 0; i < 100000000; ++i) {
        sum += i;
    }

    gettimeofday(&end, NULL);

    long seconds = end.tv_sec - start.tv_sec;
    long microseconds = end.tv_usec - start.tv_usec;
    double milliseconds = (seconds * 1000.0) + (microseconds / 1000.0);

    printf("Execution time: %.3f ms\n", milliseconds);
    return 0;
}
```
---

### Пояснення програми:
Програма використовує `gettimeofday()` для збереження часу до і після виконання фрагмента коду (тут це просте обчислення суми). Потім вона обчислює різницю в секундах та мікросекундах і виводить загальний час виконання в мілісекундах з точністю до тисячних. Функція `volatile` гарантує, що цикл не буде оптимізований компілятором.

---

### Результат роботи
![task9](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%209/task9.png)

---

# Завдання 10
---
Умова: Напишіть програму мовою C для створення послідовності випадкових чисел з плаваючою комою у діапазонах:
 (a) від 0.0 до 1.0
 (b) від 0.0 до n, де n — будь-яке дійсне число з плаваючою точкою.
 Початкове значення генератора випадкових чисел має бути встановлене так, щоб гарантувати унікальну послідовність.
Примітка: використання прапорця -Wall під час компіляції є обов’язковим.


---
### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

float random_float_0_1() {
    return (float)rand() / (float)RAND_MAX;
}

float random_float_0_n(float n) {
    return random_float_0_1() * n;
}

int main() {
    float n;
    int count = 10;

    srand((unsigned int)time(NULL));

    printf("Enter upper bound (n) for range [0.0, n]: ");
    if (scanf("%f", &n) != 1) {
        fprintf(stderr, "Invalid input.\n");
        return 1;
    }

    printf("\nRandom floats in range [0.0, 1.0]:\n");
    for (int i = 0; i < count; ++i) {
        printf("%.6f\n", random_float_0_1());
    }

    printf("\nRandom floats in range [0.0, %.2f]:\n", n);
    for (int i = 0; i < count; ++i) {
        printf("%.6f\n", random_float_0_n(n));
    }

    return 0;
}

```

### Вміст текстових файлів:
file1.txt
```
Hello, this is file1.txt.
It contains some text for testing.
This is the second line.
Enjoy reading it!
```
file2.txt
```
file2.txt is another example.
It has a few more lines.
Testing file handling in C.
Good luck with your coding!
```
subdir/file3.txt
```
This is file3.txt located in a subdirectory.
The subdirectory is part of the test.
You can see how recursion works.
Great progress!

```
---

### Пояснення програми:
Програма використовує `rand()` для генерації випадкових чисел і `srand(time(NULL))` для встановлення унікального початкового значення. Функція `random_float_0_1()` повертає число `від 0.0 до 1.0`, а `random_float_0_n(n)` — `від 0.0 до n.` Користувач вводить значення `n`, після чого генеруються 10 чисел для кожного з варіантів.

---

### Результат роботи
![task10](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%2010/task10.png)

---

# Завдання за варіантом 5

Умова: Створіть команду, яка виводить дерева викликів системних викликів (syscalls) під час виконання довільної програми без використання strace.


---
### Код програми:
```
#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```
---
``
gcc -Wall ./task_for_variant5.c -o ./task_for_variant5
ktrace -f trace.out ./task_for_variant5
kdump -f trace.out
``

---

### Пояснення програми:
Команда `ktrace -f trace.out ./task_for_variant5` запускає програму і записує всі системні виклики, які вона робить, у файл `trace.out`. Після завершення виконання `kdump -f trace.out` читає цей файл і виводить у зрозумілому вигляді всі виклики ядра `(наприклад: open, read, write, exit тощо)`, які зробила ця програма. Це дозволяє побачити, які дії на рівні операційної системи відбуваються під час виконання, подібно до `strace`, але з використанням вбудованих засобів FreeBSD.

---

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5_2.png)
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5_1.png)
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5_1.png)
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5_4.png)
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%207/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5_5.png)

---


