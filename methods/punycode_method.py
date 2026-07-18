from methods.base import BaseMethod

class PunycodeMethod(BaseMethod):
    name = "Punycode"
    description = "Punycode encoding for internationalized domain names"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return text.encode('punycode').decode()
