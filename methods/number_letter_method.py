from methods.base import BaseMethod


class NumberLetterMethod(BaseMethod):
    name = "Number-Letter"
    description = "Number-Letter, each letter becomes its position with dashes"
    category = "Other"

    def encode(self, text: str) -> str:
        parts = []
        for ch in text:
            if ch.isalpha():
                pos = ord(ch.upper()) - ord('A') + 1
                parts.append(str(pos))
            elif ch == ' ':
                parts.append('-')
        return "-".join(parts)
