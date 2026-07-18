from methods.base import BaseMethod
from Crypto.Cipher import ARC4

KEY = b'crypter_fixed_k'

class RC4Method(BaseMethod):
    name = "RC4"
    description = "RC4 stream encryption (fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        cipher = ARC4.new(KEY)
        encrypted = cipher.encrypt(text.encode())
        return encrypted.hex()
