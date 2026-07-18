from methods.base import BaseMethod


class AffineMethod(BaseMethod):
    name = "Affine"
    description = "Affine cipher, E(x) = (5x + 8) mod 26"
    category = "Cipher"

    A = 5
    B = 8

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isupper():
                x = ord(ch) - ord("A")
                result.append(chr((self.A * x + self.B) % 26 + ord("A")))
            elif ch.islower():
                x = ord(ch) - ord("a")
                result.append(chr((self.A * x + self.B) % 26 + ord("a")))
            else:
                result.append(ch)
        return "".join(result)
