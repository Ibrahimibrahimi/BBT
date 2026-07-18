from methods.base import BaseMethod


class Caesar16Method(BaseMethod):
    name = "Caesar (+16)"
    description = "Classic Caesar cipher, shift of 16"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 16) % 26 + base)
            else:
                result += ch
        return result
