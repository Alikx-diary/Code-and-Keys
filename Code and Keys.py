from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# Получаем путь к текущему каталогу
current_dir = os.path.dirname(os.path.abspath(__file__))

# Функция для генерации ключей и их сохранения в файлы
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()

    # Определяем пути для сохранения ключей
    private_key_path = os.path.join(current_dir, "private_key.pem")
    public_key_path = os.path.join(current_dir, "public_key.pem")

    # Сохранение приватного ключа в файл
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Сохранение публичного ключа в файл
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Ключи сгенерированы и сохранены в файлы '{private_key_path}' и '{public_key_path}'.")

# Функция для загрузки ключей из файлов
def load_keys():
    private_key_path = os.path.join(current_dir, "private_key.pem")
    public_key_path = os.path.join(current_dir, "public_key.pem")

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    return private_key, public_key

# Функция для шифрования данных
def encrypt_file(file_path, public_key):
    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)

    print(f"Файл {file_path} зашифрован и сохранён как {encrypted_file_path}")

# Функция для дешифрования данных
def decrypt_file(encrypted_file_path, private_key):
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    original_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(original_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"Файл {encrypted_file_path} дешифрован и сохранён как {original_file_path}")

# Выбор действия: генерация ключей, шифрование или дешифрование
action = input("Выберите действие: [G] Генерировать ключи, [E] Шифровать или [D] Дешифровать файл: ").strip().upper()

if action == "G":
    generate_keys()
elif action in ["E", "D"]:
    if not os.path.isfile(os.path.join(current_dir, "private_key.pem")) or not os.path.isfile(os.path.join(current_dir, "public_key.pem")):
        print("Ключи не найдены. Сначала сгенерируйте их.")
    else:
        private_key, public_key = load_keys()

        if action == "E":
            file_to_encrypt = input("Укажите путь к файлу, который нужно зашифровать: ")
            if os.path.isfile(file_to_encrypt):
                encrypt_file(file_to_encrypt, public_key)
            else:
                print("Файл не найден. Проверьте путь и попробуйте снова.")
        elif action == "D":
            file_to_decrypt = input("Укажите путь к файлу, который нужно дешифровать: ")
            if os.path.isfile(file_to_decrypt):
                decrypt_file(file_to_decrypt, private_key)
            else:
                print("Файл не найден. Проверьте путь и попробуйте снова.")
else:
    print("Неверный выбор. Попробуйте снова.")
