from src.files import xchacha20_poly1305
from getpass import getpass
from hashlib import sha3_256
import argparse

def ask_user_for_encryption_key():
    while True:
        key1 = getpass("Key          : ")
        key2 = getpass("Key (repeat) : ")
        if key1 == "" or key2 == "":
            print("The keys can't be an empty string, please try again")
        elif key1 != key2:
            print("The keys do not match, please try again")
        else:
            return sha3_256(key1.encode("utf-8")).digest()

def ask_user_for_decryption_key():
    while True:
        key = getpass("Key          : ")
        if key == "":
            print("The key can't be an empty string, please try again")
        else:
            return sha3_256(key.encode("utf-8")).digest()

def main():
    # Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--Encrypt", type=str,  help = "The file to encrypt")
    parser.add_argument("-d", "--Decrypt", type=str,  help = "The file to decrypt")
    args = parser.parse_args()

    if args.Encrypt:
        xchacha20_poly1305.encrypt(ask_user_for_encryption_key(), args.Encrypt)
    elif args.Decrypt:
        try:
            xchacha20_poly1305.decrypt(ask_user_for_decryption_key(), args.Decrypt)
        except:
            print("The key is either invalid or the data has been tampered with")
    else:
        print("No file provided")

if __name__ == "__main__":
    main()
