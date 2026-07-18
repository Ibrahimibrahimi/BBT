from methods.base import BaseMethod


class Crc16Cdma2000Method(BaseMethod):
    name = "CRC-16/CDMA2000"
    description = "CRC-16/CDMA2000 algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffff
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & (1 << 15):
                    crc = (crc << 1) ^ 0xc867
                else:
                    crc <<= 1
                crc &= (1 << 16) - 1
        crc ^= 0x0000
        return f"{crc:04x}"
