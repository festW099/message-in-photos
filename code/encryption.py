import sys
import os
import secrets
import hashlib
import random
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_message(message: str, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return salt + nonce + encryptor.tag + ciphertext

def get_rng_from_password(password: str) -> random.Random:
    order_salt = b'stego_order_salt_v2'
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), order_salt, 200000, dklen=32)
    seed = int.from_bytes(key, 'little')
    rng = random.Random()
    rng.seed(seed)
    return rng

def embed_data_in_image(image_path: str, data: bytes, password: str, output_path: str):
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    width, height = img.size

    full_data = len(data).to_bytes(4, 'little') + data
    total_bits = len(full_data) * 8
    max_bits = width * height * 3
    if total_bits > max_bits:
        raise ValueError(f"Изображение слишком мало. Нужно {total_bits} бит, доступно {max_bits}.")

    indices = []
    for i in range(width * height):
        for ch in range(3):
            indices.append((i, ch))
    rng = get_rng_from_password(password)
    rng.shuffle(indices)

    data_bits = ''.join(format(byte, '08b') for byte in full_data)

    new_pixels = list(pixels)
    for bit_idx, bit_char in enumerate(data_bits):
        if bit_idx >= len(indices):
            raise ValueError("Не хватает места для встраивания.")
        pix_idx, channel = indices[bit_idx]
        pixel = list(new_pixels[pix_idx])
        pixel[channel] = (pixel[channel] & 0xFE) | int(bit_char)
        new_pixels[pix_idx] = tuple(pixel)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    encoded_img = Image.new('RGB', (width, height))
    encoded_img.putdata(new_pixels)
    encoded_img.save(output_path, 'PNG')
    print(f"[✔] Сообщение успешно скрыто в {output_path}")

def main():
    if len(sys.argv) < 3:
        print("Использование: python encryption.py \"сообщение\" пароль")
        sys.exit(1)

    message = sys.argv[1]
    password = sys.argv[2]
    input_image = "photos/photo.png"
    output_image = "result/encoded_image.png"

    try:
        encrypted_data = encrypt_message(message, password)
        embed_data_in_image(input_image, encrypted_data, password, output_image)
    except Exception as e:
        print(f"[!] Ошибка: {e}")

if __name__ == "__main__":
    main()