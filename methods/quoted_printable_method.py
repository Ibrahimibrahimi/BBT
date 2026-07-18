import quopri
from methods.base import BaseMethod

class QuotedPrintableMethod(BaseMethod):
    name = "Quoted Printable"
    description = "Quoted-printable encoding for email transport"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return quopri.encodestring(text.encode()).decode()
