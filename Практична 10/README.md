# Практична робота №10-11
### Приклади коду з лекції (починаючи з Dumb Shell)
---
### Завдання 2.7  Проєкт: Dumb Shell (DumbSH)
Ціль: Створити просту оболонку, яка запускає команди користувача.

### Код завдання:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX 1024

int main() {
    char line[MAX];

    while (1) {
        printf("dumbsh> ");
        if (!fgets(line, MAX, stdin)) break;

        line[strcspn(line, "\n")] = 0;

        if (strcmp(line, "exit") == 0) break;

        pid_t pid = fork();
        if (pid == 0) {
            execlp(line, line, NULL);
            perror("exec failed");
            exit(1);
        } else {
            wait(NULL);
        }
    }

    return 0;
}
```

### Пояснення програми:
У цьому прикладі створено просту командну оболонку, яка зчитує команду від користувача, створює новий процес за допомогою `fork()` і виконує команду за допомогою `execlp()`. Основна ідея полягає в тому, що кожна введена команда виконується в окремому дочірньому процесі. Батьківський процес чекає на завершення дитини через `wait()`. Якщо користувач вводить `exit`, оболонка завершується. Я зрозуміла, як можна реалізувати базову логіку оболонки, схожу на `bash`, та як використовуються `fork + exec` разом.

---
### Завдання 2.8 Запуск dumbsh

```
1. Зберегти як dumbsh.c
Скомпілювати: gcc dumbsh.c -o dumbsh
2. Запустити:
 ./dumbsh
dumbsh> ls
dumbsh> whoami
dumbsh> exit
```

### Пояснення програми:
У цьому розділі показано, як компілювати і запускати програму `Dumb Shell`. Я зрозуміла, що потрібно зберегти файл з розширенням `.c`, скомпілювати його за допомогою `gcc`, а потім запускати як звичайну програму. Також стало зрозуміло, що ця оболонка здатна виконувати стандартні Unix-команди (наприклад, `ls, whoami`), оскільки використовує `execlp()`, який шукає команду в PATH.

### Результат запуску
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2010/task2_8.png)

---
### Завдання 2.9 API wait — деталі
```
#include <sys/wait.h>

int status;
pid_t pid = wait(&status);

if (WIFEXITED(status)) {
    printf("Exited with code %d\n", WEXITSTATUS(status));
}
```
### Демонстраційний варіант використання:
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        exit(42); 
    } else {
        int status;
        wait(&status); 

        if (WIFEXITED(status)) {
            printf("Exited with code %d\n", WEXITSTATUS(status));
        } else {
            printf("Child did not exit normally.\n");
        }
    }

    return 0;
}
```

### Пояснення програми:
Приклад з лекції показує, як отримати статус завершення дочірнього процесу після `wait()`. Я дізналася про макроси `WIFEXITED()` і `WEXITSTATUS()`, які дозволяють визначити, чи завершився процес коректно та з яким кодом. Це важливо для аналізу результату виконання дочірнього процесу. 

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2010/task2_9.png)

---
### Завдання 2.10 Fork Bomb та створення декількох дітей
```
// НЕ ЗАПУСКАЙТЕ ЦЕ! Це fork bomb!
:(){ :|:& };:

 Це призводить до вичерпання ресурсів.
Приклад створення кількох дітей:
for (int i = 0; i < 3; i++) {
    pid_t pid = fork();
    if (pid == 0) {
        printf("Child %d\n", i);
        exit(0);
    }
}
while (wait(NULL) > 0); // чекає всіх
```

### Демонстраційний варіант використання:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            printf("Child %d, PID: %d\n", i, getpid());
            exit(0);
        }
    }
    while (wait(NULL) > 0);

    printf("All children finished.\n");
    return 0;
}

```
### Пояснення програми:
У цьому прикладі демонстрація *fork bomb* — це нескінченне створення нових процесів, що може вивести систему з ладу. Потім іде інший приклад, де у циклі створюються 3 дочірні процеси, і кожен виводить свій номер. Батьківський процес чекає на завершення усіх через `wait()`. Я зрозуміла, що `fork` може використовуватись для створення багатьох паралельних процесів, але також може бути шкідливим, якщо не обмежити його використання.

---

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2010/task2_10.png)



### Завдання 2.11
```
wait(NULL); // будь-який дочірній
waitpid(-1, &status, 0); // еквівалент wait
waitpid(pid, &status, 0); // конкретний процес
waitpid(pid, &status, WNOHANG); // не блокує
```

### Демонстраційний варіант використання:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid == 0) {
        printf("Child (PID: %d) is running...\n", getpid());
        sleep(2);
        exit(42);
    } else {
        int status;

        wait(NULL);
        printf("Parent: waited with wait(NULL)\n");

        pid = fork();
        if (pid == 0) {
            sleep(1);
            exit(7);
        }

        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Parent: child exited with code %d\n", WEXITSTATUS(status));
        }

        pid_t res = waitpid(-1, &status, WNOHANG);
        if (res == 0) {
            printf("Parent: no child exited yet (non-blocking)\n");
        } else if (res == -1) {
            printf("Parent: no more children\n");
        }
    }

    return 0;
}
```

### Пояснення програми:
Цей розділ демонструє різні способи виклику `wait` і `waitpid`. Я зрозуміла, що `wait(NULL)` очікує будь-який дочірній процес, а `waitpid()` дозволяє більш точно вказати, на який процес чекати. Параметр `WNOHANG` дозволяє перевірити, чи завершився процес, без блокування основного потоку. Це корисно для побудови неблокуючих або асинхронних програм.


### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2010/task2_11.png)

---
## Завдання за варіантом 5 

Умова: Зробіть програму, в якій дочірній процес завершується з певним кодом (`exit(7)`, наприклад), а батьківський читає цей код через wait() та виводить його.

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork failed");
        return 1;
    } else if (pid == 0) {
        printf("Child process exiting with code 7\n");
        exit(7);
    } else {
        int status;
        wait(&status);
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            printf("Parent received childs exit code: %d\n", code);
        }
    }

    return 0;
}
```


### Пояснення програми:
У цій програмі використовується `fork()` для створення дочірнього процесу. Дочірній процес виконує `exit(7)`, завершуючи свою роботу з кодом 7. У батьківському процесі функція `wait(&status)` призупиняє виконання, доки дочірній процес не завершиться. Потім за допомогою макросу `WIFEXITED(status)` перевіряється, чи завершився дочірній процес нормально, і якщо так — `WEXITSTATUS(status)` дозволяє отримати код завершення. Цей код виводиться на екран, підтверджуючи успішне зчитування результату завершення дочірнього процесу.

### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2010/task_for_variant5.png)
