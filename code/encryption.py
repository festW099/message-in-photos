import sys
from PIL import Image
import os

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def encode_message(image_path: str, message: str, key: str, output_path: str):
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    width, height = img.size

    msg_bytes = message.encode('utf-8')
    encrypted_msg = xor_encrypt(msg_bytes, key.encode('utf-8'))
    data = len(encrypted_msg).to_bytes(4, 'little') + encrypted_msg
    data_bits = ''.join(format(byte, '08b') for byte in data)

    total_bits = len(data_bits)
    max_bits = width * height * 3

    if total_bits > max_bits:
        raise ValueError(f"Изображение слишком мало. Нужно {total_bits} бит, доступно {max_bits}.")

    new_pixels = []
    bit_index = 0
    for y in range(height):
        row = []
        for x in range(width):
            pixel = list(pixels[y * width + x])
            for c in range(3):
                if bit_index < total_bits:
                    bit = int(data_bits[bit_index])
                    pixel[c] = (pixel[c] & 0xFE) | bit
                    bit_index += 1
            row.append(tuple(pixel))
        new_pixels.append(row)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    encoded_img = Image.new('RGB', (width, height))
    encoded_img.putdata([pixel for row in new_pixels for pixel in row])
    encoded_img.save(output_path, 'PNG')
    print(f"Сообщение успешно скрыто в {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python encryption.py \"сообщение\" ключ")
        sys.exit(1)

    message = sys.argv[1]
    key = sys.argv[2]

    input_image = "photos/photo.png"
    output_image = "result/encoded_image.png"

    try:
        encode_message(input_image, message, key, output_image)
    except Exception as e:
        print(f"Ошибка: {e}")