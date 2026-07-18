from methods.base import BaseMethod

class StrikethroughMethod(BaseMethod):
    name = "Strikethrough"
    description = "Use Unicode combining strikethrough"
    category = "Other"

    def encode(self, text: str) -> str:
        return ''.join(c + '\u0336' for c in text)
