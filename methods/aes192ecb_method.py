from methods.base import BaseMethod
from Crypto.Cipher import AES

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY + b'01234567'  # 24 bytes for AES-192

class AES192ECBMethod(BaseMethod):
    name = "AES-192-ECB"
    description = "AES-192-ECB encryption (fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 16
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = AES.new(KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
