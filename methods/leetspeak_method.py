from methods.base import BaseMethod


class LeetspeakMethod(BaseMethod):
    name = "Leetspeak"
    description = "Converts letters to common leetspeak digit substitutions"
    category = "Custom"

    TABLE = str.maketrans({
        "a": "4", "A": "4",
        "e": "3", "E": "3",
        "i": "1", "I": "1",
        "o": "0", "O": "0",
        "s": "5", "S": "5",
        "t": "7", "T": "7",
        "l": "1", "L": "1",
    })

    def encode(self, text: str) -> str:
        return text.translate(self.TABLE)
