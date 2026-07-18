import hashlib
from methods.base import BaseMethod


class Sha1Method(BaseMethod):
    name = "SHA1"
    description = "SHA1 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha1(text.encode()).hexdigest()
