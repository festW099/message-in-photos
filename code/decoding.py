import sys
from PIL import Image

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def decode_message(image_path: str, key: str) -> str:
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for channel in pixel:
            bits.append(channel & 1)

    all_bytes = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_val = int(''.join(str(b) for b in byte_bits), 2)
        all_bytes.append(byte_val)

    if len(all_bytes) < 4:
        raise ValueError("Недостаточно данных для длины сообщения.")

    msg_len = int.from_bytes(all_bytes[:4], 'little')
    encrypted_msg = bytes(all_bytes[4:4+msg_len])

    decrypted = xor_decrypt(encrypted_msg, key.encode('utf-8'))
    try:
        return decrypted.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Неверный ключ или повреждённые данные.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python decoding.py ключ")
        sys.exit(1)

    key = sys.argv[1]
    encoded_image = "result/encoded_image.png"

    try:
        message = decode_message(encoded_image, key)
        print(f"Извлечённое сообщение: {message}")
    except Exception as e:
        print(f"Ошибка: {e}")