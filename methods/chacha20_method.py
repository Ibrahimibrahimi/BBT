import os
from methods.base import BaseMethod
from Crypto.Cipher import ChaCha20

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY + b'0123456789abcdef'  # 32 bytes for ChaCha20

class ChaCha20Method(BaseMethod):
    name = "ChaCha20"
    description = "ChaCha20 stream encryption"
    category = "Cipher"

    def encode(self, text: str) -> str:
        nonce = os.urandom(8)
        cipher = ChaCha20.new(key=KEY, nonce=nonce)
        encrypted = cipher.encrypt(text.encode())
        return nonce.hex() + encrypted.hex()
