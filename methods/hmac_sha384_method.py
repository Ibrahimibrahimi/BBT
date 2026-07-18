import hmac
import hashlib
from methods.base import BaseMethod


class HMACSHA384Method(BaseMethod):
    name = "HMAC-SHA384"
    description = "HMAC-SHA384 with key 'secret'"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hmac.new(b"secret", text.encode(), hashlib.sha384).hexdigest()
