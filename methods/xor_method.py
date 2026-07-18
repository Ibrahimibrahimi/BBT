from methods.base import BaseMethod


class XORMethod(BaseMethod):
    name = "XOR (hex)"
    description = 'XOR each byte with the fixed key "KEY" and show as hex'
    category = "Cipher"

    KEY = b"KEY"

    def encode(self, text: str) -> str:
        data = text.encode("utf-8")
        xored = bytes(b ^ self.KEY[i % len(self.KEY)] for i, b in enumerate(data))
        return xored.hex()
