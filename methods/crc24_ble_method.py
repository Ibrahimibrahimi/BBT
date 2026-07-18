from methods.base import BaseMethod


class Crc24BleMethod(BaseMethod):
    name = "CRC-24/BLE"
    description = "CRC-24/BLE algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0x555555
        for byte in data:
            crc ^= byte << 16
            for _ in range(8):
                if crc & (1 << 23):
                    crc = (crc << 1) ^ 0x00065b
                else:
                    crc <<= 1
                crc &= (1 << 24) - 1
        crc ^= 0x000000
        return f"{crc:06x}"
