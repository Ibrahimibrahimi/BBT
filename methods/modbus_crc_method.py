from methods.base import BaseMethod


class ModbusCRCMethod(BaseMethod):
    name = "Modbus CRC16"
    description = "Modbus CRC16, Modbus CRC variant"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return f"{crc:04x}"
