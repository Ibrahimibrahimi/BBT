from methods.base import BaseMethod
from Crypto.Cipher import AES

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY[:16]  # MARS needs 16-byte key

class MARSMethod(BaseMethod):
    name = "MARS"
    description = "MARS encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 16
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        try:
            from Crypto.Cipher import MARS
            cipher = MARS.new(KEY, MARS.MODE_ECB)
        except ImportError:
            cipher = AES.new(KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
