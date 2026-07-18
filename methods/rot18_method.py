from methods.base import BaseMethod


class ROT18Method(BaseMethod):
    name = "ROT18"
    description = "ROT13 for letters combined with ROT5 for digits"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base + 13) % 26 + base))
            elif ch.isdigit():
                result.append(str((int(ch) + 5) % 10))
            else:
                result.append(ch)
        return "".join(result)
