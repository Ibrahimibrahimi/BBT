from methods.base import BaseMethod


class Crc32CMethod(BaseMethod):
    name = "CRC-32C"
    description = "CRC-32C algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffffffff
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0x82f63b78
                else:
                    crc >>= 1
        crc = ((crc & 0xFF) << 8) | (crc >> 8)
        crc ^= 0xffffffff
        return f"{crc:08x}"
