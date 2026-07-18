import hmac
import hashlib
from methods.base import BaseMethod


class HMACSHA256Method(BaseMethod):
    name = "HMAC-SHA256"
    description = "HMAC-SHA256 with key 'secret'"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hmac.new(b"secret", text.encode(), hashlib.sha256).hexdigest()
