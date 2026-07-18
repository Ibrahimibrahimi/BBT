from methods.base import BaseMethod

KEYWORD = "Nihilist"

SQUARE_LETTERS = []
for ch in KEYWORD:
    if ch.upper() not in SQUARE_LETTERS:
        SQUARE_LETTERS.append(ch.upper())
for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
    if ch not in SQUARE_LETTERS:
        SQUARE_LETTERS.append(ch)

GRID = [SQUARE_LETTERS[i:i+5] for i in range(0, 25, 5)]

LOOKUP = {}
for r, row in enumerate(GRID):
    for c, ch in enumerate(row):
        LOOKUP[ch] = (r + 1) * 10 + (c + 1)


class NihilistMethod(BaseMethod):
    name = "Nihilist"
    description = "Polybius square (keyword=Nihilist) with numeric key addition"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key_vals = [LOOKUP[ch] for ch in KEYWORD.upper() if ch in LOOKUP]
        result = []
        key_idx = 0
        for ch in text.upper():
            if ch in LOOKUP:
                val = LOOKUP[ch]
                kv = key_vals[key_idx % len(key_vals)]
                result.append(str(val + kv))
                key_idx += 1
            else:
                result.append(ch)
        return " ".join(result)
