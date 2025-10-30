from src.files import xchacha20_poly1305
from getpass import getpass
from hashlib import sha3_256
import argparse

def main():
    # Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--Encrypt", type=str,  help = "The file to encrypt")
    parser.add_argument("-d", "--Decrypt", type=str,  help = "The file to decrypt")
    args = parser.parse_args()

    if args.Encrypt:
        key = sha3_256(getpass("Key: ").encode("utf-8")).digest()
        xchacha20_poly1305.encrypt(key, args.Encrypt)
    elif args.Decrypt:
        key = sha3_256(getpass("Key: ").encode("utf-8")).digest()
        xchacha20_poly1305.decrypt(key, args.Decrypt)
    else:
        print("No file provided") 

if __name__ == "__main__":
    main()
