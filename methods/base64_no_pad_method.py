import base64
from methods.base import BaseMethod


class Base64NoPadMethod(BaseMethod):
    name = "Base64 No Pad"
    description = "Base64 No Pad, base64 without padding chars"
    category = "Other"

    def encode(self, text: str) -> str:
        encoded = base64.b64encode(text.encode()).decode()
        return encoded.rstrip("=")
