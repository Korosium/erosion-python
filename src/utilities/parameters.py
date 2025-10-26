from src.constants.constants import KEY_LENGTH, NONCE_LENGTH, HEADER_LENGTH, MAGIC_NUMBER
from src.utilities.conversion import to_byte, to_hex

def pad(data:bytes, length:int, value:int) -> bytes:
    working_bytes = bytearray(data)
    for i in range(len(working_bytes), length):
        working_bytes.append(value)
    return bytes(working_bytes)

def clamp(data:bytes, length:int) -> bytes:
    if (len(data) == length): return data
    if (len(data) < length): return pad(data, length, 0)
    return data[:length]

def pad_key(key:bytes) -> bytes: return clamp(key, KEY_LENGTH)

def pad_nonce(nonce:bytes) -> bytes: return clamp(nonce, NONCE_LENGTH)

def get_encrypt_parameters(key, nonce = [], aad = []):
    return {
        "key": pad_key(to_byte(key)),
        "nonce": pad_nonce(to_byte(nonce)),
        "aad": to_byte(aad),
    }

def get_decrypt_parameters(key, path, aad):
    with open(path, "rb") as file:
        header = file.read(HEADER_LENGTH)

    return {
        "key": pad_key(to_byte(key)),
        "nonce": header[MAGIC_NUMBER:MAGIC_NUMBER+NONCE_LENGTH],
        "aad": to_byte(aad),
        "tag": to_hex(header[MAGIC_NUMBER+NONCE_LENGTH:])
    }
