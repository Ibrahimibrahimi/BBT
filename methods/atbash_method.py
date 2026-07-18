from methods.base import BaseMethod


class AtbashMethod(BaseMethod):
    name = "Atbash"
    description = "Atbash cipher — reverses the alphabet (A<->Z, B<->Y, ...)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isupper():
                result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
            elif ch.islower():
                result.append(chr(ord("z") - (ord(ch) - ord("a"))))
            else:
                result.append(ch)
        return "".join(result)
