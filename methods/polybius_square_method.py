from methods.base import BaseMethod

SQUARE = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
]

LOOKUP = {}
for r, row in enumerate(SQUARE):
    for c, ch in enumerate(row):
        LOOKUP[ch] = (r + 1, c + 1)


class PolybiusSquareMethod(BaseMethod):
    name = "Polybius Square"
    description = "5x5 grid coordinate output (e.g. 11 12 13)"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text.upper():
            if ch in LOOKUP:
                r, c = LOOKUP[ch]
                result.append(f"{r}{c}")
            elif ch == 'J':
                r, c = LOOKUP['I']
                result.append(f"{r}{c}")
            else:
                result.append(ch)
        return " ".join(result)
