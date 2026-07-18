from methods.base import BaseMethod


class Crc10AtmMethod(BaseMethod):
    name = "CRC-10/ATM"
    description = "CRC-10/ATM algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x00
        for byte in data:
            crc ^= byte << 2
            for _ in range(8):
                if crc & (1 << 9):
                    crc = (crc << 1) ^ 0x233
                else:
                    crc <<= 1
                crc &= (1 << 10) - 1
        crc ^= 0x00
        return f"{crc:02x}"
