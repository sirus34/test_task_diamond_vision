# Краткая инструкция по запуску Email Validator

## Установка
```bash
pip install dnspython
```

## Быстрый старт

### 1. Проверить email и вывести результат в консоль:
```bash
python email_checker.py emails.txt
```

### 2. Сохранить результаты в базу данных:
```bash
python email_checker.py emails.txt --db results.db
```

### 3. Изменить скорость проверки (меньше нагрузка):
```bash
python email_checker.py emails.txt --rate-limit 10 --db results.db
```

### 4. Увеличить скорость (быстрее проверка):
```bash
python email_checker.py emails.txt --rate-limit 100 --db results.db
```

## Формат файла с email
Создайте файл `emails.txt`, где каждая строка - один email:
```
test@example.com
user@domain.com
invalid-email
```

## Просмотр результатов в БД
```bash
sqlite3 results.db "SELECT email, status FROM email_checks;"
```

## Полная справка
```bash
python email_checker.py --help
```
