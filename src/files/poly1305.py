from src.constants.constants import TAG_LENGTH, HEADER_LENGTH
from src.primitives.poly1305 import Poly1305, clamp, le_bytes_to_num, num_to_8_le_bytes, num_to_16_le_bytes, pad_16_bytes
from src.utilities.utility import show_progress
import os

def mac(aad, path, key, skip_header = False):
    print("Calculating tag...")
    byte_size = os.path.getsize(path)

    poly = Poly1305(key)

    # AAD processing
    padded_aad = pad_16_bytes(aad)
    for i in range(0, len(padded_aad), TAG_LENGTH):
        poly.update(padded_aad[i:i+TAG_LENGTH])

    # File processing
    ciphertext_length = 0
    byte_processed = 0
    with open(path, "rb") as ciphertext_temp_file:
        if skip_header: ciphertext_temp_file.read(HEADER_LENGTH)
        while True:
            chunk = ciphertext_temp_file.read(TAG_LENGTH)

            if not chunk:
                break
            ciphertext_length += len(chunk)

            if len(chunk) < TAG_LENGTH:
                chunk = pad_16_bytes(chunk)

            poly.update(chunk)

            byte_processed = show_progress(chunk, byte_size, byte_processed)

    # AAD length and Ciphertext length final process
    last_part = num_to_8_le_bytes(len(aad)) + num_to_8_le_bytes(ciphertext_length)
    for i in range(0, len(last_part), TAG_LENGTH):
        poly.update(last_part[i:i+TAG_LENGTH])
    
    return poly.end()
