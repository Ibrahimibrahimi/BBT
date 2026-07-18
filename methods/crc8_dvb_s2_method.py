from methods.base import BaseMethod


class Crc8DvbS2Method(BaseMethod):
    name = "CRC-8/DVB-S2"
    description = "CRC-8/DVB-S2 algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x00
        for byte in data:
            crc ^= byte << 0
            for _ in range(8):
                if crc & (1 << 7):
                    crc = (crc << 1) ^ 0xd5
                else:
                    crc <<= 1
                crc &= (1 << 8) - 1
        crc ^= 0x00
        return f"{crc:02x}"
