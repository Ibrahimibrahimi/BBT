import zlib
from methods.base import BaseMethod


class Adler32Method(BaseMethod):
    name = "Adler32"
    description = "Adler-32 checksum (hex)"
    category = "Hash"

    def encode(self, text: str) -> str:
        return format(zlib.adler32(text.encode("utf-8")) & 0xFFFFFFFF, "08x")
