from methods.base import BaseMethod


class RunningKeyMethod(BaseMethod):
    name = "Running Key"
    description = "Vigenere cipher where the key is the plaintext itself shifted"
    category = "Cipher"

    def encode(self, text: str) -> str:
        upper = text.upper()
        result = []
        for i, ch in enumerate(upper):
            if ch.isalpha():
                base = ord("A")
                shift = ord(upper[(i + 1) % len(upper)]) - base
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(text[i])
        return "".join(result)
