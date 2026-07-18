from methods.base import BaseMethod


class HexPrefixMethod(BaseMethod):
    name = "Hex (0x prefix)"
    description = "Hex with 0x prefix, comma-separated"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return ",".join(f"0x{b:02x}" for b in text.encode("utf-8"))
