from methods.base import BaseMethod


class ReverseMethod(BaseMethod):
    name = "Reverse"
    description = "Reverses the string character by character"
    category = "Custom"

    def encode(self, text: str) -> str:
        return text[::-1]
