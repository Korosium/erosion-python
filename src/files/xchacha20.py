from src.constants.constants import STATE_SIZE, BLOCK_H_NONCE_LENGTH, NONCE_LENGTH, READ_BUFFER, HEADER_LENGTH
from src.primitives.xchacha20 import block, block_h
from src.utilities.utility import generate_timestamp, get_parent_dir
import os

def process_bytes(key, nonce, counter, chunk, offset = 0):
    sub_key = block_h(key, nonce[:BLOCK_H_NONCE_LENGTH])
    chacha20_nonce = bytes([0, 0, 0, 0] + list(nonce[BLOCK_H_NONCE_LENGTH:NONCE_LENGTH]))
    ciphertext = []
    for i in range(0, len(chunk), STATE_SIZE):
        stream = block(sub_key, counter + offset + int(i/STATE_SIZE), chacha20_nonce)
        for j in range(len(chunk[i:i+STATE_SIZE])):
            ciphertext.append(chunk[j+i] ^ stream[j])
    return bytes(ciphertext)

def encrypt(key, counter, nonce, path:str):
    filename = path.split(os.sep).pop().encode("utf-8")[:255]   
    header = bytearray([len(filename)] + list(filename))
    temp_file_path = os.path.join(get_parent_dir(path), f"{generate_timestamp()}.bin")

    i = 0
    with open(temp_file_path, "wb") as ciphertext_file:
        with open(path, "rb") as plaintext_file:
            while True:
                chunk = []
                if i == 0:
                    chunk = header + plaintext_file.read(READ_BUFFER - len(header))
                else:
                    chunk = plaintext_file.read(READ_BUFFER)
                if not chunk:
                    break
                ciphertext_file.write(process_bytes(key, nonce, counter, chunk, i))
                i += int(READ_BUFFER/STATE_SIZE)

    return temp_file_path

def decrypt(key, counter, nonce, path:str):
    filename = ""
    temp_file_path = os.path.join(get_parent_dir(path), f"{generate_timestamp()}.bin")

    i = 0
    with open(path, "rb") as ciphertext_file:
        ciphertext_file.read(HEADER_LENGTH)
        with open(temp_file_path, "wb") as plaintext_file:
            while True:
                chunk = ciphertext_file.read(READ_BUFFER)
                if not chunk:
                    break
                plaintext = process_bytes(key, nonce, counter, chunk, i)
                if i == 0:
                    filename = bytes(plaintext[1:plaintext[0]+1]).decode("utf-8")
                    plaintext_file.write(bytes(plaintext[plaintext[0]+1:]))
                else:
                    plaintext_file.write(bytes(plaintext))
                i += int(READ_BUFFER/STATE_SIZE)

    os.rename(temp_file_path, os.path.join(get_parent_dir(temp_file_path), filename))

