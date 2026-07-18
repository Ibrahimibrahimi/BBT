from methods.base import BaseMethod


class Crc16GenibusMethod(BaseMethod):
    name = "CRC-16/GENIBUS"
    description = "CRC-16/GENIBUS algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffff
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & (1 << 15):
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= (1 << 16) - 1
        crc ^= 0xffff
        return f"{crc:04x}"
