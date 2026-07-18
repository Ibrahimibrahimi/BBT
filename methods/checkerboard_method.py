from methods.base import BaseMethod


class CheckerboardMethod(BaseMethod):
    name = "Checkerboard"
    description = "Checkerboard cipher: grid-based substitution"
    category = "Cipher"

    def encode(self, text: str) -> str:
        grid = {
            'A': '11', 'B': '12', 'C': '13', 'D': '14', 'E': '15',
            'F': '21', 'G': '22', 'H': '23', 'I': '24', 'J': '25',
            'K': '31', 'L': '32', 'M': '33', 'N': '34', 'O': '35',
            'P': '41', 'Q': '42', 'R': '43', 'S': '44', 'T': '45',
            'U': '51', 'V': '52', 'W': '53', 'X': '54', 'Y': '55',
        }

        result = []
        for ch in text.upper():
            if ch in grid:
                result.append(grid[ch])
            elif ch == 'Z':
                result.append('00')
            else:
                result.append(ch)
        return "".join(result)
