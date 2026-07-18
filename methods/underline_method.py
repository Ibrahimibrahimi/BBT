from methods.base import BaseMethod

class UnderlineMethod(BaseMethod):
    name = "Underline"
    description = "Use Unicode combining double underline"
    category = "Other"

    def encode(self, text: str) -> str:
        return ''.join(c + '\u0333' for c in text)
