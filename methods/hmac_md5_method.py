import hmac
import hashlib
from methods.base import BaseMethod


class HMACMD5Method(BaseMethod):
    name = "HMAC-MD5"
    description = "HMAC-MD5 with key 'secret'"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hmac.new(b"secret", text.encode(), hashlib.md5).hexdigest()
