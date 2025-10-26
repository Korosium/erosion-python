from src.constants.constants import H, STATE_SIZE, ROUNDS, BLOCK_H_COUNTER_LENGTH, BLOCK_H_NONCE_LENGTH

def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] = (state[d] ^ state[a]) & 0xffffffff
    state[d] = rotl(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] = (state[b] ^ state[c]) & 0xffffffff
    state[b] = rotl(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] = (state[d] ^ state[a]) & 0xffffffff
    state[d] = rotl(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] = (state[b] ^ state[c]) & 0xffffffff
    state[b] = rotl(state[b], 7)

    return state

def inner_block(state):
    state = quarter_round(state, 0, 4, 8, 12)
    state = quarter_round(state, 1, 5, 9, 13)
    state = quarter_round(state, 2, 6, 10, 14)
    state = quarter_round(state, 3, 7, 11, 15)
    state = quarter_round(state, 0, 5, 10, 15)
    state = quarter_round(state, 1, 6, 11, 12)
    state = quarter_round(state, 2, 7, 8, 13)
    state = quarter_round(state, 3, 4, 9, 14)
    return state

def serialize(state):
    retval = []
    for i in range(int(STATE_SIZE / 4)):
        retval.append(state[i] & 0xff)
        retval.append((state[i] >> 8) & 0xff)
        retval.append((state[i] >> 16) & 0xff)
        retval.append((state[i] >> 24) & 0xff)
    return retval

def init(key, counter, nonce):
    return [
        H[0], H[1], H[2], H[3],
        to_uint_32(key[:4]), to_uint_32(key[4:8]), to_uint_32(key[8:12]), to_uint_32(key[12:16]),
        to_uint_32(key[16:20]), to_uint_32(key[20:24]), to_uint_32(key[24:28]), to_uint_32(key[28:32]),
        counter, to_uint_32(nonce[:4]), to_uint_32(nonce[4:8]), to_uint_32(nonce[8:12])
    ]

def rotl(n, i): return (n << i) | (n >> (32 - i))

def to_uint_32(bytes): return bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0]

def block(key, counter, nonce):
    original = init(key, counter, nonce)
    state = original.copy()
    for i in range(int(ROUNDS / 2)): state = inner_block(state)
    for i in range(int(STATE_SIZE / 4)): state[i] += original[i]
    return serialize(state)

def block_h(key, nonce):
    state = init(key, to_uint_32(nonce[:BLOCK_H_COUNTER_LENGTH]), nonce[BLOCK_H_COUNTER_LENGTH:BLOCK_H_NONCE_LENGTH])
    for _ in range(int(ROUNDS / 2)): state = inner_block(state)
    stream = serialize(state)
    return stream[:16] + stream[48:64]
