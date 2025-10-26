from src.constants.constants import READ_BUFFER, BLOCK_H_NONCE_LENGTH, NONCE_LENGTH
from src.primitives import xchacha20 as primitive_xchacha20
from src.primitives import poly1305 as primitive_poly1305
from src.files import xchacha20 as file_xchacha20
from src.files import poly1305 as file_poly1305
from src.utilities.conversion import to_hex
from src.utilities.parameters import get_encrypt_parameters, get_decrypt_parameters
from src.utilities.utility import get_parent_dir, generate_nonce
import os

def get_one_time_key(params):
    sub_key = primitive_xchacha20.block_h(params["key"], params["nonce"][:BLOCK_H_NONCE_LENGTH])
    chacha20_nonce = bytes([0, 0, 0, 0] + list(params["nonce"][BLOCK_H_NONCE_LENGTH:NONCE_LENGTH]))
    return primitive_poly1305.key_gen(sub_key, chacha20_nonce)

def generate_ciphertext_file(temp_file_path, header, path:str):
    start = True
    with open(os.path.join(get_parent_dir(path), f"{path.split(os.sep).pop()}.ero"), "wb") as erosion_file:
        with open(temp_file_path, "rb") as temp_file:
            while True:
                if start:
                    start = False
                    erosion_file.write(header)
                else:
                    chunk = temp_file.read(READ_BUFFER)
                    if not chunk:
                        break
                    erosion_file.write(chunk)
    os.remove(temp_file_path)

def generate_plaintext_file(params, tag, path):
    if params["tag"] == tag:
        file_xchacha20.decrypt(params["key"], 1, params["nonce"], path)
    else:
        raise Exception("The data is invalid")

def encrypt(key, path, nonce=generate_nonce(), aad=[]):
    params = get_encrypt_parameters(key, nonce, aad)
    one_time_key = get_one_time_key(params)
    temp_file_path = file_xchacha20.encrypt(params["key"], 1, params["nonce"], path)
    tag = file_poly1305.mac(params["aad"], temp_file_path, one_time_key)
    header = bytearray("EROSION", encoding="utf-8") + bytearray([0xcc]) + params["nonce"] + tag
    generate_ciphertext_file(temp_file_path, header, path)

def decrypt(key, path, aad=[]):
    params = get_decrypt_parameters(key, path, aad)
    one_time_key = get_one_time_key(params)
    tag = to_hex(file_poly1305.mac(params["aad"], path, one_time_key, True))
    generate_plaintext_file(params, tag, path)
    