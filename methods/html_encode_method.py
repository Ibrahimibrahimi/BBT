import html
from methods.base import BaseMethod

class HTMLEncodeMethod(BaseMethod):
    name = "HTML Entity"
    description = "HTML entity encoding for special characters"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return html.escape(text)
