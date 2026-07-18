from methods.base import BaseMethod
from Crypto.Cipher import DES

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY[:8]  # DES needs 8-byte key

class DESMethod(BaseMethod):
    name = "DES"
    description = "DES encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 8
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = DES.new(KEY, DES.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
