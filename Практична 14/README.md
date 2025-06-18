# Практична робота №14
### Приклади з лекції 
---

### Завдання 1  Простий цифровий годинник через alarm()
```
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <string.h>

void handler(int sig) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%H:%M:%S\n", tm_info);
    write(STDOUT_FILENO, buf, strlen(buf));
    alarm(1); 
}

int main() {
    signal(SIGALRM, handler); 
    alarm(1);

    while (1)
        pause();
}
```

### Пояснення програми:
Ця програма використовує застарілу, але просту функцію `alarm()` для створення таймера, який спрацьовує кожну секунду. У момент отримання сигналу `SIGALRM` викликається обробник `handler()`, який виводить поточний час у форматі `година:хвилина:секунда`. Після кожного виклику таймер переозброюється знову на 1 секунду, створюючи таким чином нескінченний цикл оновлення часу на екрані. Основним обмеженням є те, що `alarm()` дозволяє лише один таймер на процес і не підтримує точне або асинхронне керування.

### Результат запуску
![task]()

---
### Завдання 2 POSIX таймер (timer_create, timer_settime)
```
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void handler(int sig, siginfo_t *si, void *uc) {
    write(STDOUT_FILENO, "Tick\n", 5);
}

int main() {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGRTMIN, &sa, NULL);

    timer_t timerid;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    timer_create(CLOCK_REALTIME, &sev, &timerid);

    struct itimerspec its;
    its.it_value.tv_sec = 1;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 1;
    its.it_interval.tv_nsec = 0;

    timer_settime(timerid, 0, &its, NULL);

    while (1)
        pause();
}
```

### Пояснення програми:
У цій програмі демонструється сучасний механізм `POSIX`-таймерів, який дозволяє створювати кілька незалежних таймерів з високою точністю. Таймер створюється за допомогою `timer_create()` і налаштовується через `timer_settime()` на перше спрацювання через одну секунду та подальше повторення щосекунди. При кожному спрацюванні генерується сигнал `SIGRTMIN`, який обробляється асинхронним обробником `handler()` — він виводить повідомлення `"Tick"`. Цей підхід є гнучкішим і краще підходить для складних систем, де потрібно керувати багатьма таймерами або інтегрувати їх з іншими асинхронними механізмами (наприклад, epoll).

### Результат запуску
![task]()

---

## Завдання по варіантах (5 варіант)
Умова: Дослідіть, як поводиться таймер у стані sleep/suspend (через CLOCK_MONOTONIC vs CLOCK_REALTIME).

### Код завадання:
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void handler(int sig, siginfo_t *si, void *uc) {
    write(STDOUT_FILENO, "Timer fired!\n", 13);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [realtime|monotonic]\n", argv[0]);
        return 1;
    }

    clockid_t clkid;
    if (strcmp(argv[1], "realtime") == 0) {
        clkid = CLOCK_REALTIME;
    } else if (strcmp(argv[1], "monotonic") == 0) {
        clkid = CLOCK_MONOTONIC;
    } else {
        fprintf(stderr, "Unknown clock type.\n");
        return 1;
    }

    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    sigaction(SIGRTMIN, &sa, NULL);

    timer_t timerid;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;

    if (timer_create(clkid, &sev, &timerid) == -1) {
        perror("timer_create");
        return 1;
    }

    struct itimerspec its;
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timerid, 0, &its, NULL) == -1) {
        perror("timer_settime");
        return 1;
    }

    printf("Timer set for 10 seconds using %s clock. Put system to sleep now.\n", argv[1]);
    while (1)
        pause();
}
```

### Пояснення програми:
Ця програма демонструє, як поводиться `POSIX`-тймер під час переходу системи в режим сну (`sleep/suspend`), залежно від типу використовуваного годинника. Користувач може передати аргумент realtime або monotonic, щоб вибрати відповідний годинник: `CLOCK_REALTIME` базується на системному (реальному) часі, тоді як `CLOCK_MONOTONIC` — на часі, що відлічується з моменту запуску системи без урахування сну. Таймер налаштовується на однократне спрацювання через 10 секунд, а при надходженні сигналу `SIGRTMIN` спрацьовує обробник, який виводить повідомлення.

У ході виконання з’ясувалося, що при використанні `CLOCK_REALTIME` таймер спрацьовує одразу після пробудження, якщо час сну перевищив встановлений інтервал — тобто реальний час «наздоганяє» пропущене. Натомість при використанні `CLOCK_MONOTONIC` таймер призупиняється під час сну, тому відлік продовжується лише після повернення системи до активного стану. Це дозволяє вибирати тип таймера залежно від завдань: для точного вимірювання активного часу (`monotonic`) або для подій, прив’язаних до настінного годинника (`realtime`).

### Результат запуску
![task]()
