from methods.base import BaseMethod

class HexDumpMethod(BaseMethod):
    name = "Hex Dump"
    description = "Hex dump with offsets and ASCII sidebar"
    category = "Encoding"

    def encode(self, text: str) -> str:
        data = text.encode()
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hex_part:<48s}  |{ascii_part}|')
        return '\n'.join(lines)
