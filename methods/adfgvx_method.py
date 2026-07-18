from methods.base import BaseMethod

HEADERS = ['A', 'D', 'F', 'G', 'V', 'X']

CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SQUARE = [list(CHARS[i:i+6]) for i in range(0, 36, 6)]

LOOKUP = {}
for r, row in enumerate(SQUARE):
    for c, ch in enumerate(row):
        LOOKUP[ch] = (HEADERS[r], HEADERS[c])


class ADFGVXMethod(BaseMethod):
    name = "ADFGVX"
    description = "WWI German cipher using 6x6 Polybius square with A,D,F,G,V,X"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text.upper():
            if ch in LOOKUP:
                result.append(LOOKUP[ch][0] + LOOKUP[ch][1])
            else:
                result.append(ch)
        return "".join(result)
