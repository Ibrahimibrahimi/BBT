from methods.base import BaseMethod


class ROT47Method(BaseMethod):
    name = "ROT47"
    description = "ROT47 cipher — rotates printable ASCII (33-126) by 47"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            code = ord(ch)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code + 14) % 94)))
            else:
                result.append(ch)
        return "".join(result)
