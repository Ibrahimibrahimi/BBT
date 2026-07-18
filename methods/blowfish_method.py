from methods.base import BaseMethod
from Crypto.Cipher import Blowfish

BASE_KEY = b'crypter_fixed_k!'  # 16 bytes
KEY = BASE_KEY[:8]  # Blowfish needs 1-56 byte key

class BlowfishMethod(BaseMethod):
    name = "Blowfish"
    description = "Blowfish encryption (ECB, fixed key)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        data = text.encode()
        bs = 8
        pad_len = bs - (len(data) % bs)
        data += bytes([pad_len] * pad_len)
        cipher = Blowfish.new(KEY, Blowfish.MODE_ECB)
        encrypted = cipher.encrypt(data)
        return encrypted.hex()
