from methods.base import BaseMethod


class CaesarMethod(BaseMethod):
    name = "Caesar (+3)"
    description = "Classic Caesar cipher, shift of 3"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base + 3) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)
