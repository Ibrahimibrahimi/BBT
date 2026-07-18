from methods.base import BaseMethod
from Crypto.Cipher import CAST

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY[:16]  # CAST5 needs 1-16 byte key

class CAST5Method(BaseMethod):
    name = "CAST5"
    description = "CAST5 encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 8
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = CAST.new(KEY, CAST.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
