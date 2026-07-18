from methods.base import BaseMethod


class Crc16KermitMethod(BaseMethod):
    name = "CRC-16/KERMIT"
    description = "CRC-16/KERMIT algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
        crc = ((crc & 0xFF) << 8) | (crc >> 8)
        crc ^= 0x0000
        return f"{crc:04x}"
