from methods.base import BaseMethod


class Crc8Saej1850Method(BaseMethod):
    name = "CRC-8/SAE-J1850"
    description = "CRC-8/SAE-J1850 algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xff
        for byte in data:
            crc ^= byte << 0
            for _ in range(8):
                if crc & (1 << 7):
                    crc = (crc << 1) ^ 0x1d
                else:
                    crc <<= 1
                crc &= (1 << 8) - 1
        crc ^= 0xff
        return f"{crc:02x}"
