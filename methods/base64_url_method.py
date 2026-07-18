import base64
from methods.base import BaseMethod

class Base64URLMethod(BaseMethod):
    name = "Base64 URL"
    description = "URL-safe Base64 encoding (- and _ instead of + and /)"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return base64.urlsafe_b64encode(text.encode()).decode()
