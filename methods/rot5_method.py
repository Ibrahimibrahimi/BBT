from methods.base import BaseMethod


class ROT5Method(BaseMethod):
    name = "ROT5"
    description = "Digits-only rotation cipher (0-9 shifted by 5)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isdigit():
                result.append(str((int(ch) + 5) % 10))
            else:
                result.append(ch)
        return "".join(result)
