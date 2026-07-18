from methods.base import BaseMethod


class Crc24InterlakenMethod(BaseMethod):
    name = "CRC-24/INTERLAKEN"
    description = "CRC-24/INTERLAKEN algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffffff
        for byte in data:
            crc ^= byte << 16
            for _ in range(8):
                if crc & (1 << 23):
                    crc = (crc << 1) ^ 0x325834
                else:
                    crc <<= 1
                crc &= (1 << 24) - 1
        crc ^= 0xffffff
        return f"{crc:06x}"
