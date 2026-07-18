from methods.base import BaseMethod


class Base64XMLMethod(BaseMethod):
    name = "Base64 XML"
    description = "Base64 with XML entity references"
    category = "Encoding"

    def encode(self, text: str) -> str:
        import base64
        b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return "".join(f"&#{ord(c)};" if c not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=" else c for c in b64)
