from src.constants.constants import READ_BUFFER
from src.files import xchacha20_poly1305
from hashlib import sha256, sha3_256
import unittest, os

def sha256sum(path):
    hash_func = sha256()
    with open(path, 'rb') as file:
        while chunk := file.read(READ_BUFFER):
            hash_func.update(chunk)
    return hash_func.hexdigest()

class Erosion(unittest.TestCase):

    def test_001(self):
        # Arrange
        key = sha3_256(b"Fe4uR)Q48_z0&TiMF0zx7~A@fe0xh_G@").digest()
        path = "tests/files/test_file_for_erosion.txt.ero"
        expected = "82a6e87f0f44c9ac1a611bb8e75af332a73ec4de73d7de8eac568cdf73cef10d"

        # Act
        xchacha20_poly1305.decrypt(key, path)

        # Assert
        checksum = sha256sum("tests/files/test_file_for_erosion.txt")
        self.assertEqual(expected, checksum)

    def test_002(self):
        # Arrange
        key = sha3_256(b"Fe4uR)Q48_z0&TiMF0zx7~A@fe0xh_G@").digest()
        path = "tests/files/test_file_for_erosion.txt"
        nonce = [0x86, 0x62, 0x60, 0xb9, 0x7d, 0x58, 0xf0, 0x44, 0x17, 0x6e, 0x08, 0xc4, 0x18, 0x65, 0x91, 0x0a, 0x4e, 0xf6, 0xa3, 0x41, 0x7f, 0xa0, 0xfe, 0x77]
        expected = "dce8fd0e3da009b045118402619b16254a2f8928744155d18b2eb1a164e1edea"

        # Act
        xchacha20_poly1305.encrypt(key, path, nonce)

        # Assert
        checksum = sha256sum("tests/files/test_file_for_erosion.txt.ero")
        os.remove(path)
        self.assertEqual(expected, checksum)

if __name__ == '__main__':
    unittest.main()