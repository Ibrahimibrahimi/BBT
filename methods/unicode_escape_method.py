import codecs
from methods.base import BaseMethod

class UnicodeEscapeMethod(BaseMethod):
    name = "Unicode Escape"
    description = "Unicode escape sequences (\\uXXXX)"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return text.encode('unicode_escape').decode()
