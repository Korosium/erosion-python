from src.constants.constants import KEY_LENGTH, NONCE_LENGTH
from src.primitives import xchacha20 as primitive_xchacha20
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
