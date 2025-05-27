# Практичне завдання 10
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

---

### Пояснення програми:
У цій програмі використовується `fork()` для створення дочірнього процесу. Дочірній процес виконує `exit(7)`, завершуючи свою роботу з кодом 7. У батьківському процесі функція `wait(&status)` призупиняє виконання, доки дочірній процес не завершиться. Потім за допомогою макросу `WIFEXITED(status)` перевіряється, чи завершився дочірній процес нормально, і якщо так — `WEXITSTATUS(status)` дозволяє отримати код завершення. Цей код виводиться на екран, підтверджуючи успішне зчитування результату завершення дочірнього процесу.
