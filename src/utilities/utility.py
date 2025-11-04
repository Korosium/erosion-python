from src.constants.constants import KEY_LENGTH, NONCE_LENGTH, READ_BUFFER
from src.primitives import xchacha20 as primitive_xchacha20
from hashlib import sha256
import datetime, os, time

def generate_timestamp():
    return str(datetime.datetime.now()).split(".").pop(0).replace("-", "").replace(" ", "").replace(":", "")

def get_parent_dir(path:str):
    temp = path.split(os.sep)
    return os.sep.join(temp[:len(temp)-1])

def generate_nonce():
    timestamp = hex(int(time.time()*1000))[2:].zfill(KEY_LENGTH * 2)
    key = []
    for i in range(0, len(timestamp), 2): key.append(int(timestamp[i:i+2], 16))
    counter = 0xffffffff
    nonce = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    return primitive_xchacha20.block(key, counter, nonce)[:NONCE_LENGTH]

def sha256sum(path):
    hash_func = sha256()
    with open(path, 'rb') as file:
        while chunk := file.read(READ_BUFFER):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def to_hex(data):
    retval = ""
    for b in data:
        retval += hex(b)[2:].zfill(2)
    return retval
