from methods.base import BaseMethod


class CRC16Method(BaseMethod):
    name = "CRC16"
    description = "CRC16, CRC-16/CCITT polynomial 0x1021"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xFFFF
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc <<= 1
                crc &= 0xFFFF
        return f"{crc:04x}"
