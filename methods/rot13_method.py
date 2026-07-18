import codecs
from methods.base import BaseMethod


class ROT13Method(BaseMethod):
    name = "ROT13"
    description = "Classic ROT13 letter-substitution cipher"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return codecs.encode(text, "rot_13")
