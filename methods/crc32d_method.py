from methods.base import BaseMethod


class Crc32DMethod(BaseMethod):
    name = "CRC-32D"
    description = "CRC-32D algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffffffff
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xd419cc25
                else:
                    crc >>= 1
        crc = ((crc & 0xFF) << 8) | (crc >> 8)
        crc ^= 0xffffffff
        return f"{crc:08x}"
