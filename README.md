# README

## Описание

Этот скрипт написан на Python и предназначен для выполнения базовых операций шифрования и дешифрования файлов с использованием асимметричной криптографии на основе RSA. Программа позволяет:

1. Генерировать пару ключей (приватный и публичный) и сохранять их в файлы.
2. Шифровать файл с использованием публичного ключа.
3. Дешифровать файл с использованием приватного ключа.

## Зависимости

Для работы скрипта необходимо установить библиотеку `cryptography`. Это можно сделать с помощью pip:

```bash
pip install cryptography
```

## Использование

### 1. Генерация ключей

Перед шифрованием или дешифрованием необходимо сгенерировать пару ключей (приватный и публичный). Для этого выберите действие `G` при запуске скрипта:

```bash
python script_name.py
```

Затем введите `G` и нажмите Enter. Ключи будут сгенерированы и сохранены в файлы `private_key.pem` и `public_key.pem` в текущем каталоге.

### 2. Шифрование файла

Для шифрования файла выберите действие `E`. Вам потребуется указать путь к файлу, который вы хотите зашифровать. Программа использует публичный ключ для шифрования данных и создаёт зашифрованную версию файла с расширением `.enc`.

Пример запуска:

```bash
python script_name.py
```

Затем введите `E`, укажите путь к файлу, например:

```bash
/path/to/your/file.txt
```

Файл будет зашифрован и сохранён как `file.txt.enc`.

### 3. Дешифрование файла

Для дешифрования файла выберите действие `D`. Вам потребуется указать путь к зашифрованному файлу с расширением `.enc`. Программа использует приватный ключ для дешифрования данных и создаёт расшифрованную версию файла с расширением `.dec`.

Пример запуска:

```bash
python script_name.py
```

Затем введите `D`, укажите путь к зашифрованному файлу, например:

```bash
/path/to/your/file.txt.enc
```

Файл будет расшифрован и сохранён как `file.txt.dec`.

### 4. Указания

- Если ключи не найдены в текущем каталоге, программа предложит сначала сгенерировать их.
- Убедитесь, что файлы ключей (`private_key.pem` и `public_key.pem`) находятся в одном каталоге со скриптом при выполнении операций шифрования или дешифрования.

## Примечания

- Данный скрипт демонстрирует основные принципы асимметричного шифрования. В реальных приложениях, связанных с безопасностью, следует использовать более сложные методы защиты и обработки ключей.
- Будьте осторожны при работе с приватными ключами. Никогда не делитесь ими и храните их в защищённом месте.
