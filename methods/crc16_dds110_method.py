from methods.base import BaseMethod


class Crc16Dds110Method(BaseMethod):
    name = "CRC-16/DDS-110"
    description = "CRC-16/DDS-110 algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x800d
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & (1 << 15):
                    crc = (crc << 1) ^ 0x8005
                else:
                    crc <<= 1
                crc &= (1 << 16) - 1
        crc ^= 0x0000
        return f"{crc:04x}"
