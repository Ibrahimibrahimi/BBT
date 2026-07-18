from methods.base import BaseMethod

HEADERS = ['A', 'D', 'F', 'G', 'X']

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
        LOOKUP[ch] = (HEADERS[r], HEADERS[c])


class ADFGXMethod(BaseMethod):
    name = "ADFGX"
    description = "WWI cipher using 5x5 Polybius square with A,D,F,G,X"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text.upper():
            if ch in LOOKUP:
                result.append(LOOKUP[ch][0] + LOOKUP[ch][1])
            elif ch == 'J':
                result.append(LOOKUP['I'][0] + LOOKUP['I'][1])
            else:
                result.append(ch)
        return "".join(result)
