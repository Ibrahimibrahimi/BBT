from methods.base import BaseMethod
from Crypto.Cipher import AES

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY + b'0123456789abcdef'  # 32 bytes for GOST

class GOSTCipherMethod(BaseMethod):
    name = "GOST"
    description = "GOST encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 8
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        try:
            from Crypto.Cipher import GOST89
            cipher = GOST89.new(KEY)
        except ImportError:
            cipher = AES.new(KEY[:16], AES.MODE_ECB)  # AES fallback uses first 16 bytes
            data = text.encode()
            bs = 16
            pad_len = bs - (len(data) % bs)
            data += bytes([pad_len] * pad_len)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
