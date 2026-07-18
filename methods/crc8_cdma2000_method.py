from methods.base import BaseMethod


class Crc8Cdma2000Method(BaseMethod):
    name = "CRC-8/CDMA2000"
    description = "CRC-8/CDMA2000 algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xff
        for byte in data:
            crc ^= byte << 0
            for _ in range(8):
                if crc & (1 << 7):
                    crc = (crc << 1) ^ 0x9b
                else:
                    crc <<= 1
                crc &= (1 << 8) - 1
        crc ^= 0x00
        return f"{crc:02x}"
