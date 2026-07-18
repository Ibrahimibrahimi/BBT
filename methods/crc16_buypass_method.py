from methods.base import BaseMethod


class Crc16BuypassMethod(BaseMethod):
    name = "CRC-16/BUPASS"
    description = "CRC-16/BUPASS algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x0000
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
