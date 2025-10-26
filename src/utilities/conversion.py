def to_byte(data:bytes|bytearray|list|str):
    input_type = type(data)
    if(input_type == bytes): return data
    if input_type == bytearray or input_type == list: return bytes(data)
    if(input_type == str): return data.encode("utf-8")
    raise Exception(f"Invalid data type {input_type} provided")

def to_hex(arr:bytes):
    retval = ""
    for n in arr:
        retval += hex(n)[2:].zfill(2)
    return retval

def to_utf8(arr:bytes):
    return arr.decode("utf-8")
