import hashlib
from methods.base import BaseMethod


class MD5Method(BaseMethod):
    name = "MD5"
    description = "MD5 hash digest (hex)"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.md5(text.encode("utf-8")).hexdigest()
