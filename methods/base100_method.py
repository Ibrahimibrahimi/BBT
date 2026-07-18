from methods.base import BaseMethod

EMOJIS = [chr(i) for i in range(0x1F600, 0x1F600 + 96)]


class Base100Method(BaseMethod):
    name = "Base100"
    description = "Base100 (Emoji) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return "".join(EMOJIS[b % 96] for b in text.encode("utf-8"))
