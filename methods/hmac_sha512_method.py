import hmac
import hashlib
from methods.base import BaseMethod


class HMACSHA512Method(BaseMethod):
    name = "HMAC-SHA512"
    description = "HMAC-SHA512 with key 'secret'"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hmac.new(b"secret", text.encode(), hashlib.sha512).hexdigest()
