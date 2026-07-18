from methods.base import BaseMethod


class CRC8Method(BaseMethod):
    name = "CRC8"
    description = "CRC8, CRC-8 polynomial 0x07"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x00
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = ((crc << 1) ^ 0x07) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF
        return f"{crc:02x}"
