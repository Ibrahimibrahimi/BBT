import hashlib
from methods.base import BaseMethod


class Sha384Method(BaseMethod):
    name = "SHA384"
    description = "SHA384 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha384(text.encode()).hexdigest()
