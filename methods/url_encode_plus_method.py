import urllib.parse
from methods.base import BaseMethod

class URLEncodePlusMethod(BaseMethod):
    name = "URL Encode (+)"
    description = "Percent-encoding for URLs with spaces as +"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return urllib.parse.quote_plus(text)
