from methods.base import BaseMethod


class Crc10GsmMethod(BaseMethod):
    name = "CRC-10/GSM"
    description = "CRC-10/GSM algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x00
        for byte in data:
            crc ^= byte << 2
            for _ in range(8):
                if crc & (1 << 9):
                    crc = (crc << 1) ^ 0x175
                else:
                    crc <<= 1
                crc &= (1 << 10) - 1
        crc ^= 0x00
        return f"{crc:02x}"
