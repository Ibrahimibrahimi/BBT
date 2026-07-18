import hmac
import hashlib
from methods.base import BaseMethod


class HMACSHA1Method(BaseMethod):
    name = "HMAC-SHA1"
    description = "HMAC-SHA1 with key 'secret'"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hmac.new(b"secret", text.encode(), hashlib.sha1).hexdigest()
