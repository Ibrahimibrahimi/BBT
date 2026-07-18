from methods.base import BaseMethod


class Crc32PosixMethod(BaseMethod):
    name = "CRC-32/POSIX"
    description = "CRC-32/POSIX algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x00000000
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
