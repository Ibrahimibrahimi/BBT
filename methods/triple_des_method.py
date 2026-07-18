from methods.base import BaseMethod
from Crypto.Cipher import DES3

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY + b'01234567'  # 24 bytes for 3DES

class TripleDESMethod(BaseMethod):
    name = "3DES"
    description = "3DES encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 8
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = DES3.new(KEY, DES3.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
