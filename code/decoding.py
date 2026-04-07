import sys
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

def decrypt_message(encrypted_data: bytes, password: str) -> str:
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

def get_rng_from_password(password: str) -> random.Random:
    order_salt = b'stego_order_salt_v2'
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), order_salt, 200000, dklen=32)
    seed = int.from_bytes(key, 'little')
    rng = random.Random()
    rng.seed(seed)
    return rng

def extract_data_from_image(image_path: str, password: str) -> bytes:
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    width, height = img.size

    indices = []
    for i in range(width * height):
        for ch in range(3):
            indices.append((i, ch))
    rng = get_rng_from_password(password)
    rng.shuffle(indices)

    len_bits = []
    for bit_idx in range(32):
        if bit_idx >= len(indices):
            raise ValueError("Недостаточно пикселей для извлечения длины.")
        pix_idx, channel = indices[bit_idx]
        len_bits.append(pixels[pix_idx][channel] & 1)

    len_bytes = bytearray()
    for i in range(0, 32, 8):
        byte_bits = len_bits[i:i+8]
        byte_val = int(''.join(str(b) for b in byte_bits), 2)
        len_bytes.append(byte_val)
    payload_len = int.from_bytes(len_bytes, 'little')

    data_bits = []
    for bit_idx in range(32, 32 + payload_len * 8):
        if bit_idx >= len(indices):
            raise ValueError("Недостаточно пикселей для извлечения данных.")
        pix_idx, channel = indices[bit_idx]
        data_bits.append(pixels[pix_idx][channel] & 1)

    extracted = bytearray()
    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]
        if len(byte_bits) < 8:
            break
        extracted.append(int(''.join(str(b) for b in byte_bits), 2))
    return bytes(extracted)

def main():
    if len(sys.argv) < 2:
        print("Использование: python encryption.py пароль")
        sys.exit(1)

    password = sys.argv[1]
    encoded_image = "result/encoded_image.png"

    try:
        encrypted_data = extract_data_from_image(encoded_image, password)
        message = decrypt_message(encrypted_data, password)
        print(f"[✔] Извлечённое сообщение: {message}")
    except Exception as e:
        print(f"[!] Ошибка: {e}")

if __name__ == "__main__":
    main()