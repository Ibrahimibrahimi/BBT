from methods.base import BaseMethod


class Crc32AutosarMethod(BaseMethod):
    name = "CRC-32/AUTOSAR"
    description = "CRC-32/AUTOSAR algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffffffff
        for byte in data:
            crc ^= byte << 24
            for _ in range(8):
                if crc & (1 << 31):
                    crc = (crc << 1) ^ 0xf4acfb13
                else:
                    crc <<= 1
                crc &= (1 << 32) - 1
        crc ^= 0xffffffff
        return f"{crc:08x}"
