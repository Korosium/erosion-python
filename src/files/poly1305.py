from src.constants.constants import TAG_LENGTH, HEADER_LENGTH
from src.primitives.poly1305 import clamp, le_bytes_to_num, num_to_8_le_bytes, num_to_16_le_bytes, pad_16_bytes

def mac(aad, path, key, skip_header = False):
    print("Calculating tag...")
    r = le_bytes_to_num(clamp(key[:16]))
    s = le_bytes_to_num(key[16:32])
    a = 0
    p = 0x3fffffffffffffffffffffffffffffffb

    # AAD processing
    padded_aad = pad_16_bytes(aad)
    for i in range(0, len(padded_aad), TAG_LENGTH):
        n = le_bytes_to_num(padded_aad[i:i+TAG_LENGTH] + bytes([1]))
        a += n
        a = (r * a) % p

    # File processing
    ciphertext_length = 0
    with open(path, "rb") as ciphertext_temp_file:
        if skip_header: ciphertext_temp_file.read(HEADER_LENGTH)
        while True:
            chunk = ciphertext_temp_file.read(TAG_LENGTH)

            if not chunk:
                break
            ciphertext_length += len(chunk)

            if len(chunk) < TAG_LENGTH:
                chunk = pad_16_bytes(chunk)

            n = le_bytes_to_num(chunk + bytes([1]))
            a += n
            a = (r * a) % p

    # AAD length and Ciphertext length final process
    last_part = num_to_8_le_bytes(len(aad)) + num_to_8_le_bytes(ciphertext_length)
    for i in range(0, len(last_part), TAG_LENGTH):
        n = le_bytes_to_num(last_part[i:i+TAG_LENGTH] + bytes([1]))
        a += n
        a = (r * a) % p

    a += s
    return num_to_16_le_bytes(a)
