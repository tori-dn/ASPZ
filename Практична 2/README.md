# Завдання 2.1
Умова: Напишіть програму для визначення моменту, коли time_t закінчиться. Дослідіть, які зміни відбуваються в залежності від 32- та 64-бітної архітектури. Дослідіть сегменти виконуваного файлу.

---

###  Код програми
```
#include <stdio.h>
#include <time. h>
#include <limits.h>

int main() {
    time_t max_time = (time_t)~((time_t)1 << (sizeof (time_t) * 8 - 1));
    printf ("Max time_t value: %ld\n", (long)max_time);
    printf ("Date and time: %s", ctime(&max_time));

    time_t overf low_time = max_time + 1;
    printf ("After overf low: %s", ctime(&overflow_time) );

    return 0;
}
```
---
### Пояснення програми:
Ця програма демонструє роботу з максимальним значенням типу ```time_t``` (який зберігає час у секундах з початку епохи Unix) та його переповненням. На 32-бітних системах ```time_t``` може зберігати час лише до 19 січня 2038 року, після чого відбудеться переповнення та дані стануть некоректними. На 64-бітних системах обмеження набагато більші, тому ```time_t``` охоплює мільярди років без ризику переповнення. У програмі спочатку виводиться максимальне значення ```time_t``` у читабельному форматі за допомогою ```ctime()```, а потім показується, що стається після його перевищення (додавання 1) — результат стає невизначеним або від’ємним, що призводить до помилкового відображення часу.

---
### Результат роботи
![task1](https://github.com/tori-dn/ASPZ/blob/main/Практична%202/Завдання%201/task1.png)


---
# Завдання 2.2
Умова: Розгляньте сегменти у виконуваному файлі.

1. Скомпілюйте програму ```"hello world"```, запустіть ```ls -l``` для виконуваного файлу, щоб отримати його загальний розмір, і запустіть ```size```, щоб отримати розміри сегментів всередині нього.
2. Додайте оголошення глобального масиву із ```1000 int```, перекомпілюйте й повторіть вимірювання. Зверніть увагу на відмінності.
3. Тепер додайте початкове значення в оголошення масиву (пам’ятайте, що C не змушує вас вказувати значення для кожного елемента масиву в ініціалізаторі). Це перемістить масив із сегмента ```BSS``` у сегмент даних. Повторіть вимірювання. Зверніть увагу на різницю.
4. Тепер додайте оголошення великого масиву в локальну функцію. Оголосіть другий великий локальний масив з ініціалізатором. Повторіть вимірювання. Дані розташовуються всередині функцій, залишаючись у виконуваному файлі? Яка різниця, якщо масив ініціалізований чи ні?
5. Які зміни відбуваються з розмірами файлів і сегментів, якщо ви компілюєте для налагодження? Для максимальної оптимізації?

Проаналізуйте результати, щоб переконатися, що:
● сегмент даних зберігається у виконуваному файлі;
● сегмент ```BSS``` не зберігається у виконуваному файлі (за винятком примітки щодо його вимог до розміру часу виконання);
● текстовий сегмент більшою мірою піддається перевіркам оптимізації;
● на розмір файлу ```a.out``` впливає компіляція для налагод`ження, але не сегменти.

---

###  Код програми 2.2.1
```
#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```

---

### Пояснення програми:
Це проста програма яка виводить рядок "Hello, world!". Вона демонстує розміри базового виконуваного файлу. 

---
### Результат роботи
![task2_1](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_1.png)

---

###  Код програми 2.2.2
```
#include <stdio.h>

int arr[1000];

int main() {
    printf("Hello, world!\n");
    return 0;
}
```
---
### Пояснення програми:
Додавання глобального масиву збільшує  ```BSS-сегмент```, який не впливає на розмір виконуваного файлу, оскільки пам’ять під нього виділяється лише під час запуску програми. Однак це збільшує обсяг оперативної пам’яті, необхідної для роботи програми.

---
### Результат роботи
![task2_2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_2.png)

---

###  Код програми 2.2.3
```
#include <stdio.h>

int arr[1000] = {1}; 

int main() {
    printf("Hello, world!\n");
    return 0;
}
```
---
### Пояснення програми:
Ініціалізований глобальний масив ```int arr[1000] = {1}``` переміщається з BSS-сегмента (для неініціалізованих даних) у DATA-сегмент (для ініціалізованих змінних), що призводить до збільшення розміру виконуваного файлу, оскільки DATA-сегмент фізично зберігає значення у файлі, на відміну від BSS, який лише резервує пам'ять під час запуску програми.

---
### Результат роботи
![task2_3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_3.png)

---

###  Код програми 2.2.4
```
#include <stdio.h>

int main() {
    int local_arr[1000]; 
    int init_arr[1000] = {1}; 

    printf("Hello, world!\n");
    return 0;
}
```
---
### Пояснення програми:
У цій програмі створено два великі локальні масиви. Неініціалізований масив ```local_arr``` розміщується у стеку під час виконання і не впливає на розмір виконуваного файлу. Натомість масив ```init_arr```, який має ініціалізацію, включає значення в сегмент даних, тому впливає на структуру та розмір створеного виконуваного файлу після компіляції.

---
### Результат роботи
![task2_4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_4.png)

---


### Пояснення програми 2.2.5:
При збірці з опцією налагодження ```(-g)``` розмір виконуваного файлу зростає через додавання відлагоджувальної інформації, тоді як максимальна оптимізація ```(-O2)``` скорочує текстовий сегмент (код), не впливаючи на DATA/BSS. Локальні масиви у функціях не впливають на розмір файлу, оскільки пам'ять під них виділяється лише під час виконання.

---
### Результат роботи
![task2_5_1](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_5_1.png)

![task2_5_2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%202/task2_5_2.png)

---

# Завдання 2.3
Умова: Скомпілюйте й запустіть тестову програму, щоб визначити приблизне розташування стека у вашій системі:
```
#include <stdio.h>

int main() {
        int i;
        printf(&quot;The stack top is near %p\n&quot;, &amp;i);
        return 0;
}
```
Знайдіть розташування сегментів даних і тексту, а також купи всередині сегмента даних, оголосіть змінні, які будуть поміщені в ці сегменти, і виведіть їхні адреси. Збільшіть розмір стека, викликавши функцію й оголосивши кілька великих локальних масивів. Яка зараз адреса вершини стека?

Примітка: стек може розташовуватися за різними адресами на різних архітектурах та різних ОС. Хоча ми говоримо про вершину стека, на більшості процесорів стек зростає вниз, до пам’яті з меншими значеннями адрес.

---

###  Код програми 2.3.1
```
#include <stdio.h>

int main() {
    int i;
    printf("The stack top is near %p\n", (void *)&i);
    return 0;
}
```
---
### Пояснення програми:
Ця програма визначає приблизну адресу вершини стеку, виводячи адресу локальної змінної `i`. Оскільки локальні змінні зберігаються у стеку, їх адреси вказують на поточний стан стеку – чим вища адреса, тим ближче до вершини. Результат `(%p)` показує пам'ятну адресу змінної у шістнадцятковому форматі, що допомагає зрозуміти організацію стеку під час виконання програми.

---
### Результат роботи
![task3_1](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3_1.png)

---

###  Код програми 2.3.2
```
#include <stdio.h>
#include <stdlib.h>

int bss_var;
int data_var = 42;

void code_segment_function() {
    printf("This is code segment.\n");
}

int main() {
    int stack_var = 1;
    static int static_data_var = 5;
    int *heap_var = malloc(100 * sizeof(int));

    printf("Addresses of variables and functions:\n");
    printf("  &bss_var (.bss):                %p\n", (void *)&bss_var);
    printf("  &data_var (.data):              %p\n", (void *)&data_var);
    printf("  &static_data_var (.data):       %p\n", (void *)&static_data_var);
    printf("  &stack_var (stack):             %p\n", (void *)&stack_var);
    printf("  heap_var (malloc - heap):       %p\n", (void *)heap_var);
    printf("  &code_segment_function (.text): %p\n", (void *)&code_segment_function);

    free(heap_var);
    return 0;
}
```
---
### Пояснення програми:

Ця програма демонструє розподіл пам'яті у різних сегментах: BSS (неініціалізовані глобальні змінні, як `bss_var`), data (ініціалізовані глобальні та статичні змінні `data_var` і `static_data_var`), стек (локальні змінні, а саме `stack_var`), купа (динамічна пам'ять через malloc, як `heap_var`) та текстовий сегмент (код функцій, як `code_segment_function`). Виводячи їх адреси `(%p)`, можна побачити характерні діапазони пам'яті для кожного сегмента: BSS/data зазвичай знаходяться поруч у нижніх адресах, стек – у високих (і зростає вниз), купа – між ними, а код – у окремому сегменті.

---
### Результат роботи
![task3_2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3_2.png)

---

###  Код програми 2.3.3
```
#include <stdio.h>

void grow_stack() {
    int big_array1[10000];
    int big_array2[10000] = {1};

    printf("Inside grow_stack:\n");
    printf("  big_array1 address: %p\n", (void *)big_array1);
    printf("  big_array2 address: %p\n", (void *)big_array2);
}

int main() {
    int local_var;
    printf("In main:\n");
    printf("  local_var address:  %p\n", (void *)&local_var);

    grow_stack();

    return 0;
}
```
---
### Пояснення програми:
Ця програма демонструє роботу зі стеком: у функції `grow_stack()` оголошено два великі масиви - `big_array1` (неініціалізований) та `big_array2` (ініціалізований), які розміщуються у стеку під час виклику функції. Виводячи їх адреси разом з адресою локальної змінної `local_var` з `main()`, можна побачити, як стек зростає у напрямку зменшення адрес (типова поведінка для архітектур x86/x86_64). Важливо, що обидва масиви займають місце у стеку незалежно від ініціалізації, але їхнє розташування в пам'яті відрізняється через різницю у механізмах виділення.

---
### Результат роботи
![task3_3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3_3.png)

---

# Завдання 2.4
Умова: Ваше завдання – дослідити стек процесу або пригадати, як це робиться. Ви можете:

● Автоматично за допомогою утиліти gstack.

● Вручну за допомогою налагоджувача GDB.

`Користувачі Ubuntu можуть зіткнутися з проблемою: на момент написання (Ubuntu 18.04) gstack, схоже, не був доступний (альтернативою може бути pstack). Якщо gstack не працює, використовуйте другий метод – через GDB, як показано нижче. `

Спочатку подивіться на стек за допомогою `gstack(1)`. Нижче наведений приклад стека bash (аргументом команди є PID процесу): 
```
$ gstack 14654 
#0 0x00007f359ec7ee7a in waitpid () from /lib64/libc.so.6 
#1 0x000056474b4b41d9 in waitchild.isra () 
#2 0x000056474b4b595d in wait_for () 
#3 0x000056474b4a5033 in execute_command_internal () 
#4 0x000056474b4a5c22 in execute_command () 
#5 0x000056474b48f252 in reader_loop () 
#6 0x000056474b48dd32 in main () 
$ 
```
Розбір стека: 

● Номер кадру стека відображається ліворуч перед символом #.

● Кадр #0 – це найнижчий кадр. Читайте стек знизу вверх (тобто від main() – кадр #6 – до waitpid() – кадр #0).

● Якщо процес багатопотоковий, gstack покаже стек кожного потоку окремо.

Аналіз стека в режимі користувача через GDB
Щоб переглянути стек процесу вручну, використовуйте GDB, приєднавшись до процесу. Нижче наведена невелика тестова програма на C, що виконує кілька вкладених викликів функцій. Граф викликів виглядає так:

``main() --&gt; foo() --&gt; bar() --&gt; bar_is_now_closed() --&gt; pause()``

Системний виклик pause() – це приклад блокуючого виклику. Він переводить викликаючий процес у сплячий режим, очікуючи (або блокуючи) сигнал. У цьому випадку процес блокується, поки не отримає будь-який сигнал.
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define MSG &quot;In function %20s; &amp;localvar = %p\n&quot;

static void bar_is_now_closed(void) {
    int localvar = 5;
    printf(MSG, FUNCTION, &localvar);
    printf("\n Now blocking on pause()...\n");

    pause();
}

static void bar(void) {
    int localvar = 5;
    printf(MSG, FUNCTION, &localvar);
    bar_is_now_closed();
}

static void foo(void) {
    int localvar = 5;
    printf(MSG, FUNCTION, &localvar);
    bar();
}

int main(int argc, char **argv) {
    int localvar = 5;
    printf(MSG, FUNCTION, &localvar);
    foo();
    exit(EXIT_SUCCESS);
}
```

Тепер відкрийте GDB

У ньому підключіться `(attach)` до процесу (в наведеному прикладі PID = 24957) і дослідіть стек за допомогою команди backtrace (bt):
```
$ gdb --quiet 
(gdb) attach 24957 
Attaching to process 24957 
Reading symbols from <...>/hspl/unit2/stacker...done. 
Reading symbols from /lib64/libc.so.6...Reading symbols from 
/usr/lib/debug/usr/lib64/libc-2.26.so.debug...done. 
done. 
Reading symbols from /lib64/ld-linux-x86-64.so.2...Reading symbols
 ... 
(gdb) bt 
 ...
```
`Примітка`: В Ubuntu, через питання безпеки, GDB не дозволяє підключатися до довільного процесу. Це можна обійти, запустивши GDB від імені користувача root.

Аналіз того ж процесу через gstack

`` $ gstack 24957 ... ``

`gstack` — це, по суті, оболонковий скрипт (wrapper shell script), який неінтерактивно викликає GDB і запускає команду backtrace, яку ви щойно використали. Завдання: Ознайомтеся з виводом gstack і порівняйте його з GDB.

---

###  Код програми
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define MSG "In function %20s; &localvar = %p\n"

static void bar_is_now_closed(void) {
    int localvar = 5;
    printf(MSG, __func__, &localvar);
    printf("\nNow blocking on pause()...\n");
    pause();
}

static void bar(void) {
    int localvar = 5;
    printf(MSG, __func__, &localvar);
    bar_is_now_closed();
}

static void foo(void) {
    int localvar = 5;
    printf(MSG, __func__, &localvar);
    bar();
}

int main(int argc, char **argv) {
    int localvar = 5;
    printf(MSG, __func__, &localvar);
    foo();
    exit(EXIT_SUCCESS);
}

```
---
### Пояснення програми:
Ця програма демонструє роботу викликів функцій і збереження локальних змінних у стеку. Функція ```main()``` ініціалізує локальну змінну та викликає `foo()`, яка у свою чергу викликає `bar()`, а та — `bar_is_now_closed()`. Кожна з цих функцій створює власну локальну змінну й виводить її адресу, що ілюструє зростання стека. Завершується виконання блокуючим системним викликом `pause()`, який призупиняє процес до отримання сигналу — саме це дозволяє дослідити стек у момент зупинки.

---
### Результат роботи
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4.png)

### Procstat:
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4_1.png)

### GDB: 
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4_2.png)

---

# Завдання 2.5
Умова: Відомо, що при виклику процедур і поверненні з них процесор використовує стек.Чи можна в такій схемі обійтися без лічильника команд (IP), використовуючи замість нього вершину стека? Обґрунтуйте свою відповідь та наведіть приклади.

---

###  Код програми 2.5.1
```
#include <stdio.h>

void function3() {
    printf("Inside function3\n");
}

void function2() {
    printf("Inside function2\n");
    function3();
    printf("Returned to function2\n");
}

void function1() {
    printf("Inside function1\n");
    function2();
    printf("Returned to function1\n");
}

int main() {
    function1();
    printf("Back in main\n");
    return 0;
}
```
### Пояснення програми:
Це звичайний приклад вкладених викликів функцій у C. 
`main()` викликає `function1()` та — `function2()`, яка далі викликає `function3()`. Після завершення `function3()` керування повертається назад у зворотному порядку: до `function2()`, потім до `function1()` і зрештою до `main()`. За замовчуванням, ці переходи реалізуються за допомогою апаратного лічильника команд (IP) і системного стека, куди процесор зберігає адресу повернення під час виклику кожної функції.

### Результат роботи
![task5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%205/task5_1.png)

---

###  Код програми 2.5.2
```
#include <stdio.h>
#include <stdint.h>

uintptr_t stack[100];
int stack_top = -1;

void push(uintptr_t addr) {
    stack[++stack_top] = addr;
}

uintptr_t pop() {
    return stack[stack_top--];
}

void function3() {
    printf("Inside function3\n");
    ((void (*)())pop())();
}

void function2() {
    printf("Inside function2\n");
    push((uintptr_t)&&ret_point); 
    function3();
    ret_point:
    printf("Returned to function2\n");
}

void function1() {
    printf("Inside function1\n");
    push((uintptr_t)&&ret_point); 
    function2();
    ret_point:
    printf("Returned to function1\n");
}

int main() {
    function1();
    printf("Back in main\n");
    return 0;
}
```
---
### Пояснення програми:
 Ця пограма імітує механізм повернення з функцій без використання апаратного лічильника команд напряму. Тут створено власний стек на основі масиву, в який вручну записуються адреси точок повернення за допомогою GNU-розширення (адреса мітки). Замість використання системного механізму повернення з функції, `function3()` виконує `pop()` і робить стрибок на отриману адресу, використовуючи каст до функції. Таким чином, IP фактично "імітується" програмно — тобто вершина нашого власного стека використовується для визначення наступної інструкції виконання. Це демонструє, що в теорії можливо обійтись без апаратного IP, але в практичних системах це неефективно й ризиковано, тому що IP — базовий компонент управління виконанням у процесорі.

---
### Результат роботи
![task5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%205/task5_2.png)

# Завдання по варіантах (Варіант 5)
Умова: Реалізуйте стекову машину, що використовує сегмент стека для обчислень.

---

###  Код програми 
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>

#define STACK_SIZE 100
#define VARS_COUNT ('z' - 'a' + 1)

typedef struct {
    double data[STACK_SIZE];
    int top;
} Stack;

typedef struct {
    char name;
    double value;
    bool initialized;
} Variable;

void initStack(Stack *s) {
    s->top = -1;
}

bool isEmpty(Stack *s) {
    return s->top == -1;
}

bool isFull(Stack *s) {
    return s->top == STACK_SIZE - 1;
}

bool push(Stack *s, double value) {
    if (isFull(s)) {
        fprintf(stderr, "Stack overflow!\n");
        return false;
    }
    s->data[++(s->top)] = value;
    return true;
}

bool pop(Stack *s, double *value) {
    if (isEmpty(s)) {
        fprintf(stderr, "Stack underflow!\n");
        return false;
    }
    *value = s->data[(s->top)--];
    return true;
}

bool peek(Stack *s, double *value) {
    if (isEmpty(s)) {
        fprintf(stderr, "Stack is empty!\n");
        return false;
    }
    *value = s->data[s->top];
    return true;
}

bool performOperation(Stack *s, char op) {
    double a, b;
    if (!pop(s, &b) || !pop(s, &a)) return false;

    double result;
    switch (op) {
        case '+': result = a + b; break;
        case '-': result = a - b; break;
        case '*': result = a * b; break;
        case '/': 
            if (b == 0) {
                fprintf(stderr, "Division by zero!\n");
                return false;
            }
            result = a / b;
            break;
        case '^': result = pow(a, b); break;
        default:
            fprintf(stderr, "Unknown operator: %c\n", op);
            return false;
    }
    return push(s, result);
}

void initVariables(Variable *vars) {
    for (int i = 0; i < VARS_COUNT; ++i) {
        vars[i].name = 'a' + i;
        vars[i].initialized = false;
    }
}

bool assignVariable(Variable *vars, char var, double value) {
    if (var < 'a' || var > 'z') {
        fprintf(stderr, "Invalid variable name. Use a-z.\n");
        return false;
    }
    vars[var - 'a'].value = value;
    vars[var - 'a'].initialized = true;
    return true;
}

bool getVariableValue(Variable *vars, char var, double *value) {
    if (var < 'a' || var > 'z' || !vars[var - 'a'].initialized) {
        fprintf(stderr, "Variable '%c' not initialized.\n", var);
        return false;
    }
    *value = vars[var - 'a'].value;
    return true;
}

void evaluateExpression(const char *expr) {
    Stack s;
    initStack(&s);
    Variable vars[VARS_COUNT];
    initVariables(vars);

    char *token = strtok((char*)expr, " ");
    while (token != NULL) {
        if (isdigit(token[0]) || (token[0] == '-' && isdigit(token[1]))) {
            push(&s, atof(token));
        } 
        else if (strlen(token) == 1 && strchr("+-*/^", token[0])) {
            if (!performOperation(&s, token[0])) return;
        } 
        else if (token[0] == '=' && isalpha(token[1])) {
            double value;
            if (!pop(&s, &value)) return;
            assignVariable(vars, token[1], value);
        } 
        else if (isalpha(token[0])) {
            double value;
            if (!getVariableValue(vars, token[0], &value)) return;
            push(&s, value);
        } 
        else {
            fprintf(stderr, "Invalid token: %s\n", token);
            return;
        }
        token = strtok(NULL, " ");
    }

    double result;
    if (pop(&s, &result) && isEmpty(&s)) {
        printf("Result: %g\n", result);
    } else {
        fprintf(stderr, "Error: Invalid expression\n");
    }
}

int main() {
    char expr[256];
    printf("Enter RPN expression (e.g., '5 3 + =x x 2 *'): ");
    if (!fgets(expr, sizeof(expr), stdin)) {
        fprintf(stderr, "Input error\n");
        return 1;
    }
    expr[strcspn(expr, "\n")] = '\0';

    evaluateExpression(expr);
    return 0;
}

```
### Пояснення програми:
Цей код реалізує стекову машину, яка обчислює арифметичні вирази в зворотній польській нотації (RPN) — операнди записуються перед операцією (наприклад, 3 4 + замість 3 + 4). Програма підтримує основні операції (+, -, *, /, ^), збереження значень у змінних (=x) та використання змінних (x). Дані зберігаються в масивному стеку Stack, що симулює стекову пам’ять, а змінні — у масиві Variable. Програма читає вираз із консолі, розбиває його на токени, оперує стеком згідно з цими токенами й виводить фінальний результат, якщо вираз був коректний.

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%202/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%B0%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5.png)
