import urllib.parse
from methods.base import BaseMethod

class URLEncodeMethod(BaseMethod):
    name = "URL Encode"
    description = "Percent-encoding for URLs"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return urllib.parse.quote(text)
