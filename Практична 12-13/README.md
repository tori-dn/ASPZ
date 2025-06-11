# Практична робота №12-13
### Приклади коду з лекції 
---
### Завдання 1 Handling Signals
Обробка сигналів включає:
Встановлення обробника сигналу (signal handler), який викликається, коли процес отримує сигнал.
Використання функцій signal() або більш сучасної sigaction().

**Простий приклад:**
```
#include <signal.h>
#include <stdio.h>

void handle_sigint(int sig) {
    printf("Caught signal %d\n", sig);
}

int main() {
    signal(SIGINT, handle_sigint);
    while (1) {} // нескінченний цикл
}
```
Тут обробляється SIGINT — натискання Ctrl+C не завершить програму, а виведе повідомлення.

### Пояснення програми:
Програма демонструє базову обробку сигналу `SIGINT`, який зазвичай надсилається під час натискання `Ctrl+C`. Вона встановлює обробник сигналу через функцію `signal()`, який виводить повідомлення при надходженні сигналу. Основний цикл `while(1)` забезпечує безкінечне виконання, щоб дочекатися сигналу. Замість завершення, сигнал перехоплюється та просто виводиться повідомлення, тому програма не завершується сама.

### Результат запуску
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task1.png)

---
### Завдання 2 A Simple C Program that Handles a Couple of Signals`
```
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
void handle_sigint(int sig) {
    printf("Caught SIGINT (Ctrl+C)\n");
}
void handle_sigterm(int sig) {
    printf("Caught SIGTERM, exiting...\n");
    _exit(0);
}
int main() {
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigterm);
    printf("PID: %d\n", getpid());
    while (1) {
        sleep(1);
    }
}
```

### Пояснення програми:
Ця програма обробляє два сигнали — `SIGINT (від Ctrl+C)` і `SIGTERM` (який часто використовується для коректного завершення процесу). Обробник `SIGINT` просто виводить повідомлення, тоді як `SIGTERM` не тільки показує повідомлення, а й завершує програму за допомогою `_exit(0)`. У головній функції виводиться PID процесу, щоб можна було надіслати сигнал, наприклад, командою `kill`. Основний цикл з `sleep(1)` імітує фонову роботу програми.

### Результат запуску
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task2.png)

---
### Завдання 3 Masking Signals
Іноді потрібно заблокувати (замаскувати) сигнали, щоб тимчасово відкласти 
їх обробку (наприклад, під час виконання критичної секції коду).
Для цього використовуються функції: `sigprocmask()`, `sigemptyset()`, `sigaddset()`

**Приклад маскування:**
```
sigset_t set;
sigemptyset(&set);
sigaddset(&set, SIGINT);
sigprocmask(SIG_BLOCK, &set, NULL); // блокуємо SIGINT
```
Сигнал буде доставлений лише після розблокування.

### Демонстраційний варіант використання:
```
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);

    sigprocmask(SIG_BLOCK, &set, NULL);
    printf("SIGINT blocked. Try pressing Ctrl+C now (nothing will happen)...\n");
    sleep(10);

    sigprocmask(SIG_UNBLOCK, &set, NULL);
    printf("SIGINT unblocked. Now press Ctrl+C to exit.\n");

    while (1) {
        sleep(1);
    }

    return 0;
}

```
### Пояснення програми:
Ця програма демонструє, як тимчасово заблокувати сигнал `SIGINT (Ctrl+C)` за допомогою `sigprocmask()`. На 10 секунд сигнал буде ігноруватись, навіть якщо користувач спробує його надіслати — це імітує критичну секцію, де сигнал не повинен переривати виконання. Після розблокування сигнал можна знову приймати — програма реагуватиме на `Ctrl+C` і завершиться.

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task3.png)

---
### Завдання 4 Reentrant Safety and Signalling
Оскільки обробники сигналів виконуються асинхронно, вони можуть перервати будь-яку функцію. Тому важливо:
Уникати небезпечних (небезпечних для повторного входу) функцій в обробнику сигналів.
Бажано використовувати лише асинхронно-безпечні функції, наприклад: _exit(), write(), signal().

***Не можна використовувати: malloc(), print(), printf() у більшості випадків, fork(), sleep(), strtok() тощо — вони не є thread-safe або reentrant.***


### Поганий приклад:
```
#include <stdio.h>
#include <signal.h>

void handler(int sig) {
    printf("Received signal %d\n", sig);  // printf не є async-safe!
}

int main() {
    signal(SIGINT, handler);
    while (1);
}
```

### Правильний приклад:
```
#include <unistd.h>
#include <signal.h>
#include <string.h>

void handler(int sig) {
    const char *msg = "Received SIGINT\n";
    write(STDOUT_FILENO, msg, strlen(msg));  // OK: write — async-signal-safe
}

int main() {
    signal(SIGINT, handler);
    while (1);
}
```
### Пояснення програми:
У поганому прикладі використовується `printf()` в обробнику сигналу, але ця функція не є безпечною для повторного входу `(non-reentrant)` — її виклик може бути перерваний іншим сигналом, що призведе до непередбачуваної поведінки або навіть аварії програми.
У правильному прикладі використано `write()`, яка входить до списку `async-signal-safe` функцій, тобто може безпечно використовуватись в обробнику сигналів. Такий підхід гарантує, що вивід повідомлення є надійним і безпечним.

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task4.png)


---
### Завдання 5 Sigaction Flags
Функція `sigaction()` — більш контрольований спосіб установки обробників. Дає змогу:
Встановити маску сигналів під час обробки.

Вказати прапори (flags), що змінюють поведінку.

**Основні поля:**
```
struct sigaction {
    void     (*sa_handler)(int);
    sigset_t sa_mask;
    int      sa_flags;
};
```

**Корисні прапори:**
```
SA_RESTART: автоматичне повторення системних викликів, які були перервані сигналом.

SA_SIGINFO: дозволяє використовувати розширений обробник з додатковою інформацією.

SA_NOCLDWAIT: не створювати зомбі для дочірніх процесів.

SA_NODEFER: не блокувати сигнал під час його обробки.
```

### Демонстраційний варіант використання:
```
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

void handler(int sig) {
    const char *msg = "Signal caught\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

int main() {
    struct sigaction sa;

    sa.sa_handler = handler;

    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);

    sa.sa_flags = SA_RESTART | SA_NODEFER;

    sigaction(SIGINT, &sa, NULL);

    printf("Send SIGINT (Ctrl+C) or SIGTERM (kill -TERM <pid>)\n");
    while (1) pause();
}
```

### Пояснення програми:
У цій програмі використовується `sigaction()` для встановлення обробника сигналу `SIGINT`. У полі sa_mask вказано, що під час обробки сигналу буде блокуватись `SIGTERM`, тобто він не буде доставлений до завершення обробки SIGINT.
Прапор `SA_RESTART` дозволяє автоматично повторити перервані системні виклики, такі як `pause()`, а `SA_NODEFER` забезпечує, щоб сигнал `SIGINT` не блокувався під час його обробки. Це демонструє точний контроль над тим, які сигнали блокуються і як система поводиться при їх отриманні.



### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task5.png)

---
## Завдання 6 No Zombies
Коли дочірній процес завершується, але батько не викликає `wait()`, дочірній стає зомбі (process in zombie state).
Щоб уникнути зомбі:
Обробити сигнал `SIGCHLD` з `SA_NOCLDWAIT`.

Або викликати `waitpid()` або wait() у батьківському процесі.

Приклад:
``
struct sigaction sa;
sa.sa_handler = SIG_IGN;
sa.sa_flags = SA_NOCLDWAIT;
sigaction(SIGCHLD, &sa, NULL);
``

### Демонстраційний варіант використання:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

int main() {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;       
    sa.sa_flags = SA_NOCLDWAIT;    
    sigaction(SIGCHLD, &sa, NULL); 

    if (fork() == 0) {
        printf("Child exiting\n");
        _exit(0);
    }

    printf("Parent sleeping\n");
    sleep(3);
    printf("Parent done\n");
    return 0;
}
```


### Пояснення програми:
Ця програма демонструє спосіб уникнення зомбі-процесів. Зазвичай, коли дочірній процес завершується, але батьківський не викликає `wait()`, дитина переходить у стан зомбі.
Щоб уникнути цього, сигнал `SIGCHLD` ігнорується `(sa_handler = SIG_IGN)`, а прапор `SA_NOCLDWAIT` вказує, що завершені дочірні процеси не будуть залишатися як зомбі. У результаті після завершення дочірнього процесу система автоматично його прибирає, не створюючи зомбі, навіть без виклику `wait()`.

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task6.png)

---
## Завдання 7 Different Approaches to Handling Signals at High Volume
При великій кількості сигналів (наприклад, сотні SIGUSR1 за секунду), можуть виникнути проблеми:
Сигнали не буферизуються — один тип сигналу може бути доставлений один раз, навіть якщо він був надісланий кілька разів.
Можливі втрати сигналів.

Підходи до масштабної обробки:
`signalfd()` — перетворює сигнал на файловий дескриптор (Linux-specific).
`sigqueue()` — надсилає сигнал з додатковими даними (union sigval).
`RT-сигнали (SIGRTMIN..SIGRTMAX)` — можуть бути черговими (queued) і зберігають порядок.
Перехід до `event-based` моделей (наприклад, epoll/kqueue у поєднанні з signalfd).
Сигнали — потужний, але потенційно небезпечний інструмент IPC.
Важливо правильно маскувати сигнали, обирати безпечні функції та розуміти обмеження.
У сучасних системах краще уникати сигналів для масового оповіщення — використовуються черги, дескриптори, події.

---

### Демонстраційний варіант використання:
```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <string.h>
#include <poll.h>

int main() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    int sfd = signalfd(-1, &mask, 0);
    if (sfd == -1) {
        perror("signalfd");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for SIGUSR1 via signalfd...\n");

    while (1) {
        struct signalfd_siginfo fdsi;
        ssize_t s = read(sfd, &fdsi, sizeof(fdsi));
        if (s != sizeof(fdsi))
            continue;
        printf("Received SIGUSR1 via signalfd, PID: %d\n", fdsi.ssi_pid);
    }
}
```

### Пояснення програми:


### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task7.png)

---
## Завдання 8  Gracefully Handling Process Crashes
Процеси можуть аварійно завершуватися через помилки, такі як:
Сегментаційна помилка (SIGSEGV)

Ділення на нуль (SIGFPE)

Незаконна інструкція (SIGILL)

Порушення доступу до пам’яті (SIGBUS)

Мета — не просто впасти, а зробити це контрольовано, наприклад:
Зберегти лог або дамп регістрів

Очистити ресурси (файли, сокети, пам’ять)

Підхід:
Встановлення обробника для цих сигналів

Використання sigaction() з прапором SA_SIGINFO для отримання додаткових даних

---

### Демонстраційний варіант використання:
```
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/ucontext.h>

void crash_handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;

    fprintf(stderr, "\n=== Process Crash Report ===\n");
    fprintf(stderr, "Signal: %d (%s)\n", sig, 
            sig == SIGSEGV ? "Segmentation Fault" :
            sig == SIGFPE ? "Floating Point Exception" :
            sig == SIGILL ? "Illegal Instruction" :
            sig == SIGBUS ? "Bus Error" : "Unknown Signal");
    
    fprintf(stderr, "Fault address: %p\n", info->si_addr);

#if defined(__x86_64__)
    #if defined(REG_RIP)
        fprintf(stderr, "Instruction Pointer (RIP): 0x%016llx\n", 
               (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
        fprintf(stderr, "Stack Pointer (RSP): 0x%016llx\n", 
               (unsigned long long)uc->uc_mcontext.gregs[REG_RSP]);
    #else
        fprintf(stderr, "Instruction Pointer: 0x%016llx\n", 
               (unsigned long long)uc->uc_mcontext.gregs[16]);
    #endif
#else
    fprintf(stderr, "Register info available only for x86_64\n");
#endif

    fprintf(stderr, "=== End of Report ===\n\n");

    _exit(EXIT_FAILURE);
}

int main() {
    struct sigaction sa;
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL); 
    sigaction(SIGFPE, &sa, NULL);   
    sigaction(SIGILL, &sa, NULL);  
    sigaction(SIGBUS, &sa, NULL); 

    int *p = NULL;
    *p = 123; 

    // Інші приклади аварій:
    // int x = 5 / 0;       // SIGFPE
    // asm volatile("ud2"); // SIGILL
    // *(volatile int*)0xBadAddress = 123; // SIGBUS

    printf("Program completed normally\n");
    return EXIT_SUCCESS;
}
```


### Пояснення програми:
У демонстраційному варіанті показується, як обробити аварійне завершення програми (наприклад, через `SIGSEGV`) контрольовано. Замість того щоб просто "впасти", програма виводить детальну інформацію: який саме сигнал надійшов, яка адреса стала причиною помилки та значення регістрів (наприклад, `RIP` і `RSP` для `x86_64`). Це дозволяє діагностувати проблему та безпечно завершити програму, зберігши важливу інформацію для налагодження.


### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task8.png)

---
## Завдання 9  Trapping and Extracting Information from a Crash
Обробник сигналу з SA_SIGINFO отримує додаткову інформацію через `siginfo_t`:

```
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handler(int sig, siginfo_t *info, void *ucontext) {
    printf("Caught signal %d\n", sig);
    printf("Fault address: %p\n", info->si_addr);
    exit(1);
}
int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    int *p = NULL;
    *p = 42; // викликає SIGSEGV
}
```


### Пояснення програми:
Ця програма демонструє використання розширеного обробника сигналів із прапором `SA_SIGINFO`, що дозволяє отримати додаткову інформацію про помилку. Коли програма викликає сегментаційну помилку (`SIGSEGV`) — через запис у NULL-вказівник (`*p = 42;`) — спрацьовує обробник `handler`. Через параметр `siginfo_t *info` він виводить тип сигналу та адресу, яка спричинила аварію (`info->si_addr`)`. Це дозволяє зрозуміти, де саме сталася помилка, і коректно завершити програму.


### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task9.png)

---
## Завдання 10  Register Dumping
Після аварії процесу можна отримати доступ до контексту процесора, зокрема до регістрів через `ucontext_t`.
Фрагмент:
`` #include <ucontext.h>
void handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
#if defined(__x86_64__)
    printf("RIP: %llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
#endif
}
``
Реєстри залежать від архітектури: REG_RIP, REG_EIP, REG_RSP, REG_RAX тощо.

---

### Демонстраційний варіант використання:
```
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>

void handler(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
#if defined(__x86_64__)
    fprintf(stderr, "Crash at RIP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
#endif
    _exit(1);
}

int main() {
    struct sigaction sa = {0};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    int *p = NULL;
    *p = 1; // triggers SIGSEGV
}
```


### Пояснення програми:
Ця програма демонструє, як можна перехопити аварійний сигнал `SIGSEGV`(сегментаційне порушення доступу) та вивести значення регістра командного лічильника (`RIP`) на архітектурі `x86_64`. Для цього використовується розширений обробник сигналів (`sa_sigaction`), який отримує третій аргумент — `ucontext_t`, що містить повний стан регістрів процесора під час аварії.
У середині обробника виконується приведення `void*` context до типу `ucontext_t*`, після чого виводиться значення `REG_RIP`, яке вказує на адресу інструкції, що спричинила збій. Програма спеціально викликає помилку доступу (`*p = 1`; де p — це `NULL`) для тестування цього механізму.

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task10.png)

---
## Завдання 11 Sleeping Correctly
Звичайні функції сну (sleep, usleep, nanosleep) можуть бути перервані сигналами.
Рішення:
Повторно викликати nanosleep() з оновленим залишком
Або використовувати sigsuspend()

Приклад:
`` struct timespec req = {1, 0}; // 1 сек
while (nanosleep(&req, &req) == -1 && errno == EINTR); ``


---

### Демонстраційний варіант використання:
```
#include <stdio.h>
#include <time.h>
#include <errno.h>

int main() {
    struct timespec req = {1, 0}; // 1 секунда
    while (nanosleep(&req, &req) == -1 && errno == EINTR) {

    }
    puts("Wake up!");
    return 0;
}

```


### Пояснення програми:
Ця програма демонструє безпечне використання функції `nanosleep()` у випадку, коли процес може отримувати сигнали. Зазвичай `sleep()` або `nanosleep()` можуть бути перервані сигналом — у такому випадку вони завершуються раніше, ніж вказаний час. Щоб коректно "доспати" залишок часу, програма перевіряє, чи `nanosleep()` повернула помилку `-1`, а errno встановлено в `EINTR` (interrupted by signal). У такому випадку цикл повторює виклик nanosleep() з оновленим значенням залишку часу (`req`). Це дозволяє програмі спати повну вказану тривалість навіть попри переривання сигналами.


### Результат виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task11.png)

---
## Завдання 12 Real-Time Signals
Сигнали в діапазоні SIGRTMIN до SIGRTMAX мають такі переваги:
Буферизовані (queued) — не втрачаються

Можна надсилати разом з даними через sigqueue()

Надсилання RT-сигналу з даними:
 `` union sigval val;
val.sival_int = 123;
sigqueue(pid, SIGRTMIN, val); ``

В обробнику:
`` void handler(int sig, siginfo_t *info, void *ctx) {
    printf("Received data: %d\n", info->si_value.sival_int);
}
``

---

### Демонстраційний варіант використання:

**Надсилання RT-сигналу з даними: Надсилання RT-сигналу з даними:**
```
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main() {
    union sigval val;
    val.sival_int = 123;

    pid_t pid = getpid(); // getpid() -> отримаємо з програми 2
    sigqueue(pid, SIGRTMIN, val);
    return 0;
}
```

**Обробник сигналу з доступом до даних:**
```
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

void handler(int sig, siginfo_t *info, void *ctx) {
    printf("Received RT signal %d with data: %d\n", sig, info->si_value.sival_int);
}

int main() {
    printf("Receiver PID: %d\n", getpid());
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO; 
    sa.sa_sigaction = handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGRTMIN, &sa, NULL);

    pause(); 
    return 0;
}

```

### Пояснення програми:
Цей приклад демонструє використання реального **часу (real-time) сигналів** — сигналів у діапазоні `SIGRTMIN` до `SIGRTMAX`. Вони, на відміну від звичайних, можуть передаватися разом із додатковими даними, які зберігаються у структурі `sigval`.

У **першій частині** ```task12_1.c``` (`sigqueue()`), процес надсилає собі сигнал `SIGRTMIN` із цілим значенням 123, використовуючи структуру `union sigval`. Відправлення здійснюється функцією `sigqueue()`, яка дозволяє вкласти додаткову інформацію в сигнал (на відміну від звичайного `kill()`).

У **другій частині** ```task12_2.c``` обробник сигналу встановлюється через `sigaction()` з прапором `SA_SIGINFO`, що дозволяє отримати розширену інформацію про сигнал, зокрема значення, передане через `sigqueue()`. Коли сигнал надходить, викликається функція `handler()`, яка виводить номер сигналу та передане значення (`info->si_value.sival_int`).

### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task12.png)

---
## Завдання 13 Sending Signals
Сигнали можна надсилати з процесу або з shell:

Shell:
`` kill -SIGUSR1 <pid> ``

C API:
``` 
kill(pid, SIGTERM);
sigqueue(pid, SIGUSR1, val); // з даними 
```


---

### Демонстраційний варіант використання:
**kill() — надсилає звичайний сигнал без даних:**

```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    kill(pid, SIGTERM);

    return 0;
}
```

**Надсилання RT-сигналу з даними через sigqueue()**
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    union sigval val;
    val.sival_int = 777; // Передаємо ціле число

    sigqueue(pid, SIGUSR1, val);

    return 0;
}
```

**програма-приймач**
```
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void handler(int sig, siginfo_t *info, void *ctx) {
    if (sig == SIGUSR1)
        printf("Received SIGUSR1 with data: %d\n", info->si_value.sival_int);
    else if (sig == SIGTERM)
        printf("Received SIGTERM\n");
}

int main() {
    printf("Receiver PID: %d\n", getpid());

    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while (1) pause();
}
```

### Пояснення програми:
У цьому завданні відтворена демонстрація надсилання сигналів між процесами за допомогою системних викликів `kill()` і `sigqueue()`. Усього використовується три окремі програми:

task13_1.c — програма, яка надсилає звичайний сигнал `SIGTERM` до вказаного процесу за допомогою `kill(pid, SIGTERM)`. Цей сигнал не містить додаткових даних і просто викликає стандартну реакцію в процесі-приймачі.

task13_2.c — програма, яка надсилає реальний сигнал `SIGUSR1` з додатковим цілим числом через s`igqueue()`. Завдяки цьому в обробнику сигналів можна отримати та обробити передані дані.

task13_3.c — це програма-приймач, яка очікує на сигнали `SIGTERM` та `SIGUSR1`. Вона встановлює обробники сигналів, зокрема обробник `SIGUSR1`, що приймає додаткові дані через `siginfo_t` (використовується прапор `SA_SIGINFO`). Вона виводить свій `PID`, який потрібно вказати у програмах-відправниках.


### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task13.png)

---
## Завдання 14 A Small Publisher-Subscriber Type of Application
У цьому прикладі:
Підписник (subscriber) очікує сигнали


Видавець (publisher) надсилає RT-сигнали з payload

```
Subscriber:
void handler(int sig, siginfo_t *info, void *ctx) {
    printf("Received %d from PID %d with data %d\n",
        sig, info->si_pid, info->si_value.sival_int);
}

int main() {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGRTMIN, &sa, NULL);
    printf("PID: %d\n", getpid());
    while (1) pause();
}

Publisher:
int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    union sigval val;
    val.sival_int = 42;
    sigqueue(pid, SIGRTMIN, val);
}
```
### Пояснення програми: ПОЯСНЕННЯ ТА РЕЗУЛЬТАТ ЗАПУСКУ ОПИСАНИЙ У ЗАВДАННІ 17.

---
## Завдання 15 Alternative Signal-Handling Techniques
Замість signal()/sigaction() використовують:
- signalfd() — Linux-specific API, перетворює сигнал у файловий дескриптор

- eventfd()/epoll() — для інтеграції з event loop

- Threads + sigwaitinfo() — синхронне очікування сигналів у спеціальному потоці


---

### Демонстраційний варіант використання:
**1. signalfd() — обробка сигналів через дескриптор (Linux-only)**
```
#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

int main() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    int sfd = signalfd(-1, &mask, 0);

    printf("Waiting for SIGUSR1 (via signalfd)...\n");

    struct signalfd_siginfo fdsi;
    read(sfd, &fdsi, sizeof(fdsi)); 
    printf("Got signal %d from PID %d\n", fdsi.ssi_signo, fdsi.ssi_pid);
    return 0;
}
```


### Пояснення програми:
У цьому завданні демонструються альтернативні способи обробки сигналів, які можуть бути корисні в асинхронних або багатопоточних застосунках:
Реалізація з `signalfd()` перетворює сигнал (`SIGUSR1`) на подію, що зчитується з файлового дескриптора. Це дозволяє обробляти сигнали як звичайні події у файловому ввід/виводі (наприклад, разом з `select(), poll(), epoll()` тощо). Сигнал попередньо блокується (sigprocmask()), і його обробка здійснюється через `read()` з дескриптора.


### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task15.png)

---
## Завдання 16 The sigwaitinfo and the sigtimedwait System Calls
Дозволяють синхронно очікувати сигнал і отримати про нього дані (подібно до обробника, але не асинхронно).
Приклад:
```
sigset_t set;
sigemptyset(&set);
sigaddset(&set, SIGUSR1);
sigprocmask(SIG_BLOCK, &set, NULL);

siginfo_t info;
sigwaitinfo(&set, &info);

printf("Got signal %d from PID %d\n", info.si_signo, info.si_pid);
```
Переваги:
Немає асинхронного виклику
Безпечніше працювати з ресурсами


---
### Демонстраційний варіант використання:

```
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);

    sigprocmask(SIG_BLOCK, &set, NULL);

    printf("Receiver PID: %d\n", getpid());
    printf("Waiting for SIGUSR1 synchronously...\n");

    siginfo_t info;
    sigwaitinfo(&set, &info); 

    printf("Got signal %d from PID %d\n", info.si_signo, info.si_pid);
    return 0;
}
```

### Пояснення програми:
Ця програма демонструє використання `sigwaitinfo()` для синхронного очікування сигналу `SIGUSR1`. Спочатку ми додаємо `SIGUSR1` до маски сигналів, блокуємо його за допомогою `sigprocmask()`, і після цього чекаємо на його прихід через `sigwaitinfo()`. На відміну від звичайних обробників сигналів, цей спосіб є синхронним — програма блокується до приходу сигналу, що робить його безпечнішим при роботі з ресурсами (не викликається асинхронно під час виконання іншого коду). Для зручності `PID` будемо виводити одразу, на відміну від минулого завдання — це дозволяє легко надіслати сигнал з іншого терміналу без потреби шукати PID окремо. Після надсилання сигналу програма виводить номер сигналу та `PID` процесу, який його надіслав.


### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task16.png)

---
## Завдання 17 Source Code (Збірка компонентів)
// subscriber.c
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void handler(int sig, siginfo_t *info, void *ctx) {
    printf("Received %d from PID %d with value %d\n",
           sig, info->si_pid, info->si_value.sival_int);
}
int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &sa, NULL);
    printf("Subscriber PID: %d\n", getpid());
    while (1) pause();
}

// publisher.c
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    pid_t pid = atoi(argv[1]);
    union sigval val;
    val.sival_int = 99;
    sigqueue(pid, SIGRTMIN, val);
}
Компіляція:
gcc subscriber.c -o subscriber
gcc publisher.c -o publisher

---


### Пояснення програми:
Це приклад взаємодії між двома окремими програмами — **"підписник" (subscriber)** та **"видавець" (publisher)** — через реальний час сигналів (real-time signals).

Програма `subscriber.c` запускає нескінченний цикл очікування сигналу `SIGRTMIN`. Вона встановлює обробник за допомогою `sigaction()` із прапором `SA_SIGINFO`, що дозволяє отримати додаткову інформацію про сигнал, включаючи PID відправника та передане значення. При запуску виводиться PID процесу, який треба буде вказати при запуску іншої програми. Для зручності, PID виводиться одразу.

Програма `publisher.c` очікує PID підписника як аргумент командного рядка. Вона надсилає сигнал `SIGRTMIN` із додатковим цілим значенням 99 за допомогою sigqueue().

### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task17.png)

---
## Завдання по варіантах 5
Умова: Напишіть багатопоточну програму, яка виконує критичну обчислювальну задачу, і у випадку SIGSEGV відновлюється з останньої збереженої контрольної точки.


---

### Демонстраційний варіант використання:
```
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <setjmp.h>

#define NUM_THREADS 2

sigjmp_buf jump_buffers[NUM_THREADS];  
pthread_t threads[NUM_THREADS];
int has_failed[NUM_THREADS] = {0};  // додано флаг для кожного потоку

void segv_handler(int sig, siginfo_t *info, void *ucontext) {
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_equal(threads[i], pthread_self())) {
            printf("[Thread %d] Caught SIGSEGV, recovering...\n", i);
            siglongjmp(jump_buffers[i], 1);
        }
    }
    printf("Unknown thread caught SIGSEGV\n");
    exit(1);
}

void* thread_func(void* arg) {
    int tid = *(int*)arg;
    printf("[Thread %d] Starting...\n", tid);

    if (sigsetjmp(jump_buffers[tid], 1) == 0) {
        printf("[Thread %d] Set checkpoint\n", tid);
    } else {
        printf("[Thread %d] Recovered from segmentation fault!\n", tid);
        has_failed[tid] = 1;
    }

    sleep(1);
    if (tid == 1 && !has_failed[tid]) {
        printf("[Thread %d] Causing segmentation fault...\n", tid);
        int *p = NULL;
        *p = 42;
    }

    printf("[Thread %d] Finished normally.\n", tid);
    return NULL;
}

int main() {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segv_handler;
    sigaction(SIGSEGV, &sa, NULL);

    int ids[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, thread_func, &ids[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    puts("All threads finished.");
    return 0;
}
```

### Пояснення програми:
Ця багатопотокова програма демонструє механізм обробки аварійного завершення (`SIGSEGV`) з подальшим відновленням потоку до останньої контрольної точки, заданої за допомогою `sigsetjmp()`.
У програмі створюються два потоки. Для кожного потоку зберігається власна контрольна точка у масиві `jump_buffers`. Потік №1 навмисне викликає помилку сегментації (доступ до нульового вказіника), що спричиняє сигнал ` SIGSEGV`. Обробник сигналу визначає, який потік спричинив помилку, і повертає його виконання до останнього `sigsetjmp`, завдяки `siglongjmp`.


### Результати виконання:
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%2012-13/folder%20with%20png/task_for_var5.png)

