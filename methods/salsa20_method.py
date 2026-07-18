import os
from methods.base import BaseMethod
from Crypto.Cipher import Salsa20

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY + b'0123456789abcdef'  # 32 bytes for Salsa20

class Salsa20Method(BaseMethod):
    name = "Salsa20"
    description = "Salsa20 stream encryption"
    category = "Cipher"

    def encode(self, text: str) -> str:
        nonce = os.urandom(8)
        cipher = Salsa20.new(key=KEY, nonce=nonce)
        encrypted = cipher.encrypt(text.encode())
        return nonce.hex() + encrypted.hex()
