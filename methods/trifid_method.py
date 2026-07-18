from methods.base import BaseMethod

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#"
GROUPS = [ALPHABET[i:i+9] for i in range(0, 27, 9)]

LOOKUP = {}
for g, group in enumerate(GROUPS):
    for idx, ch in enumerate(group):
        row = idx // 3
        col = idx % 3
        LOOKUP[ch] = (g + 1, row + 1, col + 1)

COORD_LOOKUP = {}
for ch, coord in LOOKUP.items():
    COORD_LOOKUP[coord] = ch


class TrifidMethod(BaseMethod):
    name = "Trifid"
    description = "3D fractionation cipher using 27-character alphabet"
    category = "Cipher"

    def encode(self, text: str) -> str:
        text = text.upper().replace(" ", "")
        text = text.replace("J", "I") + "#"

        groups = []
        rows = []
        cols = []
        for ch in text:
            if ch in LOOKUP:
                g, r, c = LOOKUP[ch]
                groups.append(g)
                rows.append(r)
                cols.append(c)

        coords = groups + rows + cols
        n = len(text)
        result = []
        for i in range(n):
            g = coords[i]
            r = coords[n + i]
            c = coords[2 * n + i]
            if (g, r, c) in COORD_LOOKUP:
                result.append(COORD_LOOKUP[(g, r, c)])
        return "".join(result)
