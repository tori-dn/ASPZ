# Завдання 4.1
Умова: Скільки пам’яті може виділити malloc(3) за один виклик?
Параметр malloc(3) є цілим числом типу даних size_t, тому логічно максимальне число, яке можна передати як параметр malloc(3), — це максимальне значення size_t на платформі (sizeof(size_t)). У 64-бітній Linux size_t становить 8 байтів, тобто 8 * 8 = 64 біти. Відповідно, максимальний обсяг пам’яті, який може бути виділений за один виклик malloc(3), дорівнює 2^64. Спробуйте запустити код на x86_64 та x86. Чому теоретично максимальний обсяг складає 8 ексабайт, а не 16?

---
### Пояснення:

Функція `malloc(3)` у мові C виділяє динамічну пам’ять і приймає аргумент типу `size_t`, який є беззнаковим цілим числом. У 64-бітних системах, таких як x86_64, `size_t` має розмір 8 байтів, тобто може представляти значення до `2^64 - 1`, що теоретично дозволяє виділити до 16 ексабайт пам’яті в одному виклику `malloc()`. Це виглядає як величезний обсяг, який на практиці, звісно, недоступний.

Однак у реальності обсяг пам’яті, яку можна виділити, значно менший. Це зумовлено тим, що сучасні 64-бітні процесори, попри 64-бітну адресацію, фактично використовують лише 48 біт для адрес користувацького простору. Отже, навіть якщо `size_t` може представляти значення до 16 ЕБ, реально доступно лише до 256 ТБ адресованого простору, і то не все з нього може бути використано для `malloc()`.

Крім того, реалізації `malloc()` в стандартних бібліотеках (наприклад, glibc або jemalloc) і саме ядро операційної системи також накладають обмеження. Зазвичай, спроба виділити занадто великий обсяг пам’яті призведе до того, що `malloc()` поверне `NULL`, сигналізуючи про помилку. Також слід ураховувати інші фактори, як-от фрагментацію пам’яті, зарезервовані області, системні обмеження та ресурси.

Отже, хоча з формальної точки зору `malloc()` може приймати значення до 16 ЕБ у 64-бітній системі, фактична межа — значно менша, і на практиці виділення навіть кількох терабайт за один раз малоймовірне або неможливе. Це демонструє різницю між теоретичною можливістю типу даних і реальними обмеженнями апаратного та програмного середовища.

---

# Завдання 4.2
Умова: Що станеться, якщо передати malloc(3) від’ємний аргумент? Напишіть тестовий випадок, який обчислює кількість виділених байтів за формулою num = xa * xb. Що буде, якщо num оголошене як цілочисельна змінна зі знаком, а результат множення призведе до переповнення? Як себе поведе malloc(3)? Запустіть програму на x86_64 і x86.


---

### Код програми

```
// task2_1.c
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
```

```
// task2_2.c
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
```
---
### Пояснення програми:
Передача до `malloc(3)` від’ємного значення, як у випадку, коли результат множення двох великих цілих чисел зі знаком переповнює тип int, призводить до непередбачуваної поведінки, оскільки від’ємне значення при неявному приведенні до `size_t` (беззнаковий тип) стає великим позитивним числом. У таких випадках `malloc()` намагається виділити гігантську кількість пам’яті (наприклад, кілька терабайт або навіть ексабайт), що зазвичай завершується невдачею та поверненням `NULL`, але сам факт некоректного використання типів може призвести до серйозних помилок у програмі. Тому при обчисленні розміру пам’яті завжди слід використовувати беззнакові типи або перевіряти переповнення перед передачею значення у `malloc()`.

---

### Результат роботи
![task2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2.png)

![task2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_1.png)

---

# Завдання 4.3
Умова: Що станеться, якщо використати `malloc(0)`? Напишіть тестовий випадок, у якому `malloc(3)` повертає `NULL` або вказівник, що не є `NULL`, і який можна передати у `free()`. Відкомпілюйте та запустіть через `ltrace`. Поясніть поведінку програми.

---

### Код програми

```
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
```

---
### Пояснення програми:
Програма викликає `malloc(0)`, тобто просить у системи виділити нуль байтів памʼяті. За стандартом мови C така ситуація має невизначену, але допустиму поведінку: функція `malloc(0)` може повернути або `NULL`, або коректний, але непридатний до використання вказівник, який усе ж можна передати у `free()`.

У програмі перевіряється, що саме повернув `malloc(0)`. Якщо це `NULL`, виводиться повідомлення про це. Якщо ж повернено не-NULL вказівник, програма повідомляє його значення і передає у `free()` — це безпечно, навіть якщо за ним не стоїть жодної реальної памʼяті. При запуску на більшості систем (наприклад, з glibc чи jemalloc) `malloc(0)` повертає ненульовий вказівник, який не можна використовувати для запису/читання, але його можна звільнити.

Отже, програма демонструє, що `malloc(0)` не обовʼязково повертає `NULL`, і показує, що навіть у цьому випадку виклик `free()` не призводить до помилки.

---

### Результат роботи
![task3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3.png)

---

# Завдання 4.4
Умова: Чи є помилки у такому коді?
```
void *ptr = NULL;
while (<some-condition-is-true>) {
    if (!ptr)
        ptr = malloc(n);
    [... <використання 'ptr'> ...]
    free(ptr);
}
```
Напишіть тестовий випадок, який продемонструє проблему та правильний варіант коду.

---

### Код програми

Неправильний варіант:
```
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
```
Правильний варіант:
```
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
```

---
### Пояснення програми:
У початковому (неправильному) варіанті коду використовується умовне виділення пам’яті лише один раз за допомогою `malloc(n)`, після чого в кожній ітерації відбувається звільнення цієї памʼяті через `free(ptr)`. Проблема полягає в тому, що після `free()` вказівник `ptr` не скидається в `NULL`, і на наступній ітерації перевірка `if (!ptr)` вже не спрацьовує — отже, програма продовжує використовувати звільнену памʼять, що є класичною помилкою типу `use-after-free`. Це може призвести до непередбачуваної поведінки, збоїв або уразливостей у програмі. У правильному варіанті код переписано так, що виділення і звільнення памʼяті відбувається в кожній ітерації незалежно, тому `ptr` завжди дійсний, і програма працює коректно.

---

### Результат роботи
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4.png)

---

# Завдання 4.5
Умова: Що станеться, якщо `realloc(3)` не зможе виділити пам’ять? Напишіть тестовий випадок, що демонструє цей сценарій.


---

### Код програми
Тестовий приклад, що демонструє помилку realloc:
```
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
```
Тестовий приклад — безпечний варіант:
```
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
```
---
### Пояснення програми:
У цьому завданні досліджується поведінка функції `realloc(3)`, коли вона не може виділити запрошену кількість пам’яті. У першому варіанті коду виклик `realloc` напряму змінює вміст змінної `ptr`. Якщо `realloc` не зможе виділити пам’ять і поверне `NULL`, значення вказівника буде втрачено, і раніше виділена пам’ять стане недоступною — виникне витік пам’яті. У другому, безпечному варіанті результат `realloc` спочатку зберігається у тимчасовий вказівник `tmp`. Якщо виділення не вдалося, старий ptr усе ще вказує на дійсну памʼять, яку можна безпечно звільнити. Такий підхід дозволяє уникнути витоку памʼяті й робить код більш надійним.

---

### Результат роботи
![task5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%205/task5.png)

---

# Завдання 4.6
Умова: Якщо realloc(3) викликати з NULL або розміром 0, що станеться? Напишіть тестовий випадок.

---

### Код програми
Тестовий випадок:
```
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
```

---
### Пояснення програми:
Цей тестовий випадок демонструє особливу поведінку `realloc(3)` у трьох сценаріях. Коли `realloc` викликається з `NULL` і ненульовим розміром, він поводиться як `malloc`, тобто виділяє нову область пам’яті й повертає вказівник на неї. Якщо викликати `realloc` з ненульовим вказівником і розміром 0, стандарт визначає, що памʼять має бути звільнена, а функція повертає `NULL`. Однак, залежно від реалізації стандартної бібліотеки, результат може бути або `NULL`, або `не-NULL`, хоча памʼять у будь-якому випадку вважається звільненою. Останній випадок — `realloc(NULL, 0)` — не визначений жорстко: деякі реалізації повертають `NULL`, інші — виділяють невелику область. В усіх випадках результат необхідно перевіряти й обробляти обережно, щоб уникнути витоків пам’яті або використання невалідного вказівника.

---

### Результат роботи
![task6](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%206/task6.png)

---

# Завдання 4.7
Умова: Перепишіть наступний код, використовуючи reallocarray(3):
```
struct sbar *ptr, *newptr;
ptr = calloc(1000, sizeof(struct sbar));
newptr = realloc(ptr, 500*sizeof(struct sbar));
```
Порівняйте результати виконання з використанням ltrace.

---

### Код програми
```
#include <stdio.h>
#include <stdlib.h>

struct sbar {
  int data;
};

int main() {
  struct sbar *ptr, *newptr;

  ptr = calloc(1000, sizeof (struct sbar));
  if (!ptr) {
    perror ("calloc failed");
    return 1;
  }

  printf ("calloc successful: ptr = %p\n", ptr);

  newptr = reallocarray (ptr, 500, sizeof (struct sbar));
  if (!newptr) {
    perror ("reallocarray failed");
    free (ptr);
    return 1;
  }

  printf ("reallocarray successful: newptr = %p\n", newptr);

  free (newptr);
  return 0;
}
```

---
### Пояснення програми:
У цьому завданні ми використовуємо `reallocarray(3)` замість `realloc(3)` для більш безпечного перевиділення пам’яті. Функція `reallocarray(ptr, nmemb, size)` автоматично перевіряє переповнення під час множення `nmemb * size`, що часто є джерелом помилок у `realloc`, коли обчислення розміру виконується вручну. У програмі спочатку виділяється пам’ять для 1000 структур `sbar` за допомогою `calloc`, яка ініціалізує пам’ять нулями. Потім пам’ять зменшується до розміру для 500 структур, вже через `reallocarray`. Якщо пам’ять не може бути перевиділена, програма коректно звільняє попередній блок і завершується з повідомленням про помилку. Використання `ltrace` дозволяє спостерігати, як саме викликаються `calloc` і `reallocarray`, і переконатися в тому, що заміна `realloc` на `reallocarray` не впливає на функціональність, але підвищує надійність програми.

---

### Результат роботи
![task7](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%207/task7.png)

---

# Завдання по варіантах (варіант 5)
Умова: Використайте mprotect для створення області пам’яті, що неможливо змінювати.

---

### Код програми
```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

void sigsegv_handler(int sig) {
    printf("Caught SIGSEGV (attempt to write to read-only memory)\n");
    exit(1);
}

int main() {
    signal(SIGSEGV, sigsegv_handler);

    size_t pagesize = getpagesize();
    void *addr = mmap(NULL, pagesize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    strcpy((char*)addr, "Hello, protected memory!");
    printf("Before mprotect: %s\n", (char*)addr);

    if (mprotect(addr, pagesize, PROT_READ) == -1) {
        perror("mprotect");
        munmap(addr, pagesize);
        return 1;
    }

    printf("Memory is now read-only.\n");

    ((char*)addr)[0] = 'X'; 

    munmap(addr, pagesize);
    return 0;
}
```

---
### Пояснення програми:
У цій програмі демонструється використання системного виклику `mprotect` для створення області пам’яті, доступної лише для читання. Спочатку за допомогою mmap виділяється одна сторінка пам’яті з правами читання та запису. Потім у цю пам’ять записується рядок, після чого виклик mprotect змінює дозволи на `PROT_READ`, тобто лише на читання. Подальша спроба змінити вміст цієї пам’яті (запис символу 'X') призводить до порушення доступу, яке викликає сигнал `SIGSEGV`. Програма перехоплює цей сигнал обробником `sigsegv_handler`, який виводить повідомлення та завершує виконання. Цей приклад наочно демонструє, як можна використовувати механізми захисту пам’яті в Unix-системах для запобігання випадковим або зловмисним модифікаціям даних.

---

### Результат роботи
![task_for_variant5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%204%20/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%B0%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5.png)

---

