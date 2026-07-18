from methods.base import BaseMethod


class Crc24OpenpgpMethod(BaseMethod):
    name = "CRC-24/OPENPGP"
    description = "CRC-24/OPENPGP algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xb704ce
        for byte in data:
            crc ^= byte << 16
            for _ in range(8):
                if crc & (1 << 23):
                    crc = (crc << 1) ^ 0x864cfb
                else:
                    crc <<= 1
                crc &= (1 << 24) - 1
        crc ^= 0x000000
        return f"{crc:06x}"
