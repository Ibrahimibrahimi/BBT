from methods.base import BaseMethod


class XORFFMethod(BaseMethod):
    name = "XOR (0xFF)"
    description = "XOR each byte with 0xFF, output as hex string"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for byte in text.encode("utf-8"):
            result.append(f"{byte ^ 0xFF:02x}")
        return "".join(result)
