from src.constants.constants import KEY_LENGTH, TAG_LENGTH
from src.primitives.xchacha20 import block

class Poly1305:

    def __init__(self, key):
        self.r = le_bytes_to_num(clamp(key[:16]))
        self.s = le_bytes_to_num(key[16:32])
        self.a = 0
        self.p = 0x3fffffffffffffffffffffffffffffffb

    def update(self, chunk):
        n = le_bytes_to_num(chunk + bytes([1]))
        self.a += n
        self.a = (self.r * self.a) % self.p

    def end(self):
        self.a += self.s
        return num_to_16_le_bytes(self.a)

def clamp(r):
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252
    return r

def le_bytes_to_num(n):
    retval = 0
    for i in reversed(range(len(n))):
        retval += n[i] << i * 8
    return retval

def num_to_8_le_bytes(n):
    retval = []
    for i in reversed(range(8)):
        retval.append((n >> i * 8) & 0xff)
    retval.reverse()
    return bytearray(retval)

def num_to_16_le_bytes(a):
    retval = []
    for i in reversed(range(16)):
        retval.append((a >> i * 8) & 0xff)
    retval.reverse()
    return bytes(retval)

def pad_16_bytes(data:bytes):
    to_pad = 16 - len(data) % 16
    if (to_pad == 16): to_pad = 0
    retval = bytearray(data)
    for _ in range(to_pad):
        retval.append(0)
    return retval

def key_gen(key, nonce):
    return block(key, 0, nonce)[:KEY_LENGTH]

def mac(msg, key):
    poly = Poly1305(key)
    for i in range(0, len(msg), TAG_LENGTH):
        poly.update(msg[i:i+TAG_LENGTH])
    return poly.end()
