from methods.base import BaseMethod


class Base58Method(BaseMethod):
    name = "Base58"
    description = "Bitcoin-style Base58 encoding (no 0/O/I/l)"
    category = "Encoding"

    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def encode(self, text: str) -> str:
        data = text.encode("utf-8")
        num = int.from_bytes(data, "big")

        encoded = ""
        while num > 0:
            num, rem = divmod(num, 58)
            encoded = self.ALPHABET[rem] + encoded

        # preserve leading zero bytes as leading '1's, per convention
        leading_zeros = len(data) - len(data.lstrip(b"\x00"))
        return "1" * leading_zeros + (encoded or "1" if not data else encoded)
