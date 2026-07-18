from methods.base import BaseMethod


class Crc15CanMethod(BaseMethod):
    name = "CRC-15/CAN"
    description = "CRC-15/CAN algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x000
        for byte in data:
            crc ^= byte << 7
            for _ in range(8):
                if crc & (1 << 14):
                    crc = (crc << 1) ^ 0x4599
                else:
                    crc <<= 1
                crc &= (1 << 15) - 1
        crc ^= 0x000
        return f"{crc:03x}"
