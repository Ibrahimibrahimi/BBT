from methods.base import BaseMethod


class Crc12GsmMethod(BaseMethod):
    name = "CRC-12/GSM"
    description = "CRC-12/GSM algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x000
        for byte in data:
            crc ^= byte << 4
            for _ in range(8):
                if crc & (1 << 11):
                    crc = (crc << 1) ^ 0xc06
                else:
                    crc <<= 1
                crc &= (1 << 12) - 1
        crc ^= 0x000
        return f"{crc:03x}"
