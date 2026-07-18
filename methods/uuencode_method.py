import codecs
from methods.base import BaseMethod

class UUEncodeMethod(BaseMethod):
    name = "UUencode"
    description = "Unix-to-Unix encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return codecs.encode(text.encode(), 'uu').decode()
