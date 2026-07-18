from methods.base import BaseMethod
from Crypto.Cipher import AES

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY + b'0123456789abcdef'  # 32 bytes for AES-256

class AES256ECBMethod(BaseMethod):
    name = "AES-256-ECB"
    description = "AES-256-ECB encryption (fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 16
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = AES.new(KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
