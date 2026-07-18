from methods.base import BaseMethod
from Crypto.Cipher import ARC2

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY[:16]  # RC2 needs 1-16 byte key

class RC2Method(BaseMethod):
    name = "RC2"
    description = "RC2 encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 8
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = ARC2.new(KEY, ARC2.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
