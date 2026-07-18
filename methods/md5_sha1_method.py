import hashlib
from methods.base import BaseMethod


class Md5Sha1Method(BaseMethod):
    name = "MD5-SHA1"
    description = "MD5-SHA1 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("md5-sha1", text.encode()).hexdigest()
