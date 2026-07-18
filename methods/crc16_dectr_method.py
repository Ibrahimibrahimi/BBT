from methods.base import BaseMethod


class Crc16DectrMethod(BaseMethod):
    name = "CRC-16/DECT-R"
    description = "CRC-16/DECT-R algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x0001
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & (1 << 15):
                    crc = (crc << 1) ^ 0x0589
                else:
                    crc <<= 1
                crc &= (1 << 16) - 1
        crc ^= 0x0001
        return f"{crc:04x}"
