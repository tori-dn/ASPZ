# Завдання 9.1
Умова: Напишіть програму, яка читає файл /etc/passwd за допомогою команди getent passwd, щоб дізнатись, які облікові записи визначені на вашому комп’ютері.
 Програма повинна визначити, чи є серед них звичайні користувачі (ідентифікатори UID повинні бути більші за 500 або 1000, залежно від вашого дистрибутива), окрім вас.


---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#define LINE_LEN 1024
#define UID_THRESHOLD 1000

int main() {
    FILE *fp;
    char line[LINE_LEN];
    char *username;
    uid_t current_uid = getuid();

    fp = popen("getent passwd", "r");
    if (!fp) {
        perror("popen");
        return 1;
    }

    printf("Regular users (UID > %d), excluding current user (UID %d):\n", UID_THRESHOLD, current_uid);

    while (fgets(line, LINE_LEN, fp)) {
        char *fields[7];
        char *token = strtok(line, ":");
        int i = 0;

        while (token && i < 7) {
            fields[i++] = token;
            token = strtok(NULL, ":");
        }

        if (i == 7) {
            uid_t uid = (uid_t)atoi(fields[2]);
            if (uid > UID_THRESHOLD && uid != current_uid) {
                printf("User: %s (UID: %d)\n", fields[0], uid);
            }
        }
    }

    pclose(fp);
    return 0;
}
```
---

### Пояснення програми:
Ця програма виконує команду `getent passwd`, читає її вивід построково, розділяє кожен рядок за символом : і витягує `UID` користувача (третє поле). Вона порівнює цей UID з пороговим значенням 1000 (що типово для звичайних користувачів у FreeBSD) і виводить імена всіх таких користувачів, крім поточного (визначеного за допомогою `getuid()`).

---

### Результат роботи
![task1](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B0%D0%B4%D0%BD%D0%BD%D1%8F%201/task1.png)

---

# Завдання 9.2
Умова: Напишіть програму, яка виконує команду `cat /etc/shadow` від імені адміністратора, хоча запускається від звичайного користувача.
 (Ваша програма повинна робити необхідне, виходячи з того, що конфігурація системи дозволяє отримувати адміністративний доступ за допомогою відповідної команди.)


---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>

int main() {
    int status = system("sudo cat /etc/shadow");
    if (status != 0) {
        fprintf(stderr, "Failed to read /etc/shadow. Are you allowed to use sudo?\n");
        return 1;
    }
    return 0;
}
```
---

### Пояснення програми:
Це завдання виклнано на `Ubuntu`, тому що файл У `FreeBSD` файл `/etc/shadow` не існує. Натомість паролі зберігаються у файлі `/etc/master.passwd`, який має схожі обмеження доступу. Однак виклик `cat /etc/shadow` у FreeBSD завершиться помилкою, оскільки такого файлу немає.


Ця програма виконує системну команду `sudo cat /etc/shadow`, яка виводить вміст файлу `/etc/shadow`, доступного лише адміністратору. Вона використовує функцію `system()` для запуску зовнішньої команди з правами суперкористувача. Якщо в системі налаштовано відповідний дозвіл у файлі `/etc/sudoers`, користувач може виконати цю команду без введення пароля. У разі помилки виводиться повідомлення про відмову доступу або невдалу спробу виконання.


---

### Результат роботи
![task2](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B0%D0%B4%D0%BD%D0%BD%D1%8F%202/task2.png)

---

# Завдання 9.3
Умова: Напишіть програму, яка від імені root копіює файл, який вона перед цим створила від імені звичайного користувача. Потім вона повинна помістити копію у домашній каталог звичайного користувача.
Далі, використовуючи звичайний обліковий запис, програма намагається змінити файл і зберегти зміни. Що відбудеться?
Після цього програма намагається видалити цей файл за допомогою команди rm. Що відбудеться?


---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    const char *orig_file = "/tmp/user_file.txt";
    const char *copy_file = "/root/Desktop/copied_file.txt";  

    FILE *f = fopen(orig_file, "w");
    if (!f) {
        perror("Failed to create original file");
        return 1;
    }
    fprintf(f, "Original content\n");
    fclose(f);
    printf("User created file: %s\n", orig_file);

    printf("Copying file as root...\n");
    int status = system("sudo cp /tmp/user_file.txt /home/your_username/copied_file.txt && sudo chown root:root /home/your_username/copied_file.txt");
    if (status != 0) {
        fprintf(stderr, "Copy failed\n");
        return 1;
    }

    printf("Trying to modify copied file as user...\n");
    f = fopen(copy_file, "a");
    if (!f) {
        perror("Modification failed");
    } else {
        fprintf(f, "Trying to append content\n");
        fclose(f);
        printf("Modification succeeded\n");
    }

    printf("Trying to delete copied file as user...\n");
    status = system("rm /home/your_username/copied_file.txt");
    if (status != 0) {
        fprintf(stderr, "Delete failed\n");
    } else {
        printf("Delete succeeded\n");
    }

    return 0;
}

```
---

### Пояснення програми:
Ця програма демонструє, як файл, створений звичайним користувачем, копіюється `root`-користувачем у домашній каталог, після чого звичайний користувач намагається змінити й видалити копію. Спочатку програма створює текстовий файл із вмістом "Original content" у `/tmp`. Потім вона запускає команду sudo cp для копіювання файлу в домашній каталог користувача, змінює власника копії на `root`. Далі вона намагається дописати текст до цієї копії, що завершується помилкою через відсутність прав запису. Нарешті, програма пробує видалити файл — і це вдається, оскільки користувач має право видаляти файли у власному каталозі, навіть якщо сам файл належить `root`.

---

### Результат роботи
![task3](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%203/task3.png)

---

# Завдання 9.4
Умова: Напишіть програму, яка по черзі виконує команди whoami та id, щоб перевірити стан облікового запису користувача, від імені якого вона запущена.
 Є ймовірність, що команда id виведе список різних груп, до яких ви належите. Програма повинна це продемонструвати.

---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Running 'whoami':\n");
    system("whoami");

    printf("\nRunning 'id':\n");
    system("id");

    return 0;
}
```
---

### Пояснення програми:
Ця програма демонструє, від імені якого користувача вона запущена, та до яких груп належить цей користувач. Спочатку вона виконує команду `whoami`, яка виводить ім’я поточного користувача. Потім вона запускає команду `id`, яка показує числові та символьні ідентифікатори користувача `(UID)`, основної групи `(GID)`, а також список усіх додаткових груп, у які він входить. Це дозволяє оцінити, які права має користувач у системі, і як вони можуть впливати на доступ до файлів чи системних ресурсів.

---

### Результат роботи
![task4](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%204/task4.png)

---

# Завдання 9.5
Умова: Напишіть програму, яка створює тимчасовий файл від імені звичайного користувача. Потім від імені суперкористувача використовує команди chown і chmod, щоб змінити тип володіння та права доступу.
 Програма повинна визначити, в яких випадках вона може виконувати читання та запис файлу, використовуючи свій обліковий запис.


---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    const char *file = "/tmp/temp_file.txt";

    FILE *f = fopen(file, "w");
    if (!f) {
        perror("User: cannot create file");
        return 1;
    }
    fprintf(f, "Temporary content\n");
    fclose(f);
    printf("User: created file %s\n", file);

    printf("Root: changing ownership and permissions...\n");
    int status = system("sudo chown root:wheel /tmp/temp_file.txt && sudo chmod 600 /tmp/temp_file.txt");
    if (status != 0) {
        fprintf(stderr, "Root: failed to change ownership or permissions\n");
        return 1;
    }

    printf("User: trying to read file...\n");
    f = fopen(file, "r");
    if (!f) {
        perror("Read failed");
    } else {
        char buffer[100];
        fgets(buffer, sizeof(buffer), f);
        printf("Read succeeded: %s", buffer);
        fclose(f);
    }

    printf("User: trying to write to file...\n");
    f = fopen(file, "a");
    if (!f) {
        perror("Write failed");
    } else {
        fprintf(f, "Trying to write more data\n");
        fclose(f);
        printf("Write succeeded\n");
    }

    return 0;
}

```
---

### Пояснення програми:
Ця програма створює тимчасовий файл від імені звичайного користувача в директорії `/tmp`, а потім за допомогою команд `chown` і `chmod`, виконаних від імені суперкористувача, змінює власника файлу на `root` і встановлює обмеження на права доступу (лише для читання та запису root). Після цього програма намагається прочитати та дописати в файл. Вона виведе помилки при спробах читання та запису, якщо користувач не має відповідних прав доступу. Це демонструє, як права власності та доступу можуть обмежувати можливості взаємодії з файлами в системі.

---

### Результат роботи
![task5](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%205/task5.png)

---

# Завдання 9.6
Умова: Напишіть програму, яка виконує команду ls -l, щоб переглянути власника і права доступу до файлів у своєму домашньому каталозі, в /usr/bin та в /etc.
 Продемонструйте, як ваша програма намагається обійти різні власники та права доступу користувачів, а також здійснює спроби читання, запису та виконання цих файлів.


---

### Код програми:
```
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Running 'ls -l' on home directory:\n");
    system("ls -l ~");

    printf("\nRunning 'ls -l' on /usr/bin directory:\n");
    system("ls -l /usr/bin");

    printf("\nRunning 'ls -l' on /etc directory:\n");
    system("ls -l /etc");

    printf("\nAttempting to read a file in /usr/bin...\n");
    system("cat /usr/bin/ls");

    printf("\nAttempting to write to a file in /etc...\n");
    system("echo 'Test' > /etc/test_file.txt");

    printf("\nAttempting to execute a file from /usr/bin...\n");
    system("/usr/bin/ls");

    return 0;
}
```
---

### Пояснення програми:
Ця програма виконує команду `ls -l` для трьох директорій — домашнього каталогу користувача, `/usr/bin` і `/etc`, щоб відобразити власників і права доступу до файлів у цих каталогах. Потім вона намагається продемонструвати різні операції з файлами, зокрема спроби читання, запису та виконання файлів, щоб показати, як права доступу (читання, запис, виконання) можуть обмежувати доступ до файлів залежно від їх власника та встановлених прав. Програма намагається виконати ці операції на файлах, що належать різним користувачам або групам, і демонструє можливі помилки доступу, якщо права на це не дозволяють.

---

### Результат роботи
![task6](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%206/task6_1.png)
![task6](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%206/task6_2.png)
![task6](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%206/task6_3.png)

---

# Завдання за варіантом 5
Умова: Змоделюйте ситуацію, де користувач має лише права на запис до файлу, але не може його прочитати. Як це можливо, і які наслідки для безпеки або роботи програм?

---

### Пояснення програми:
Щоб змоделювати ситуацію, де користувач має тільки права на запис у файл, але не може його прочитати, можна встановити для файлу права доступу таким чином, щоб лише право запису було дозволене, а право читання заборонене.

### Як це можна зробити? 
Спочатку створюємо файл: `touch /tmp/test_file.txt`
Змінюємо права доступу на файл: `chmod 200 /tmp/test_file.txt`
Це дає лише право на запис для власника файлу. В результаті:
- Власник може записувати в файл (право w).
- Власник не може читати з файлу (немає права r).
- Власник не може виконувати файл (немає права x).

Перевіряємо права доступу: `ls -l /tmp/test_file.txt`

### Наслідки для безпеки та роботи програм:
Безпека: Така ситуація може бути корисною для запису даних у файл, наприклад, для журналювання або зберігання тимчасових даних, де важливо, щоб файл не міг бути прочитаний без відповідних прав. Це обмежує доступ до вмісту файлу для інших користувачів, забезпечуючи певний рівень конфіденційності. Однак якщо програма потребує читання файлу для подальших операцій, така конфігурація може призвести до помилок.

Програми: Для програм, які намагаються прочитати цей файл, це призведе до помилки, оскільки вони не зможуть отримати доступ до його вмісту (наприклад, помилка Permission denied при спробі відкрити файл на читання). Програми, що повинні працювати з таким файлом, повинні мати обробку помилок для коректного реагування на відсутність прав доступу.

---

### Результат роботи
![task](https://github.com/tori-dn/ASPZ/blob/main/%D0%9F%D1%80%D0%B0%D0%BA%D1%82%D0%B8%D1%87%D0%BD%D0%B0%209/%D0%97%D0%B0%D0%B2%D0%B4%D0%B0%D0%BD%D0%BD%D1%8F%20%D0%BF%D0%BE%20%D0%B2%D0%B0%D1%80%D1%96%D0%B0%D0%BD%D1%82%D0%B0%D1%85/task_for_variant5.png)

---

