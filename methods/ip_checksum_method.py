from methods.base import BaseMethod


class IPChecksumMethod(BaseMethod):
    name = "IP Checksum"
    description = "IP Checksum, RFC 1071 Internet checksum"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        if len(data) % 2:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) | data[i + 1]
            total += word
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        checksum = ~total & 0xFFFF
        return f"{checksum:04x}"
