from methods.base import BaseMethod


class Crc32Bzip2Method(BaseMethod):
    name = "CRC-32/BZIP2"
    description = "CRC-32/BZIP2 algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffffffff
        for byte in data:
            crc ^= byte << 24
            for _ in range(8):
                if crc & (1 << 31):
                    crc = (crc << 1) ^ 0x04c11db7
                else:
                    crc <<= 1
                crc &= (1 << 32) - 1
        crc ^= 0xffffffff
        return f"{crc:08x}"
