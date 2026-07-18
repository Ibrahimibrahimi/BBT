from methods.base import BaseMethod


class Crc16ModbusMethod(BaseMethod):
    name = "CRC-16/MODBUS"
    description = "CRC-16/MODBUS algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xffff
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xa001
                else:
                    crc >>= 1
        crc = ((crc & 0xFF) << 8) | (crc >> 8)
        crc ^= 0x0000
        return f"{crc:04x}"
