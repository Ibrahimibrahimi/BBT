import zlib
from methods.base import BaseMethod


class CRC32Method(BaseMethod):
    name = "CRC32"
    description = "CRC32 checksum (hex)"
    category = "Hash"

    def encode(self, text: str) -> str:
        return format(zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF, "08x")
