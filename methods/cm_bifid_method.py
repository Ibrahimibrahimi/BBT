from methods.base import BaseMethod


class CmBifidMethod(BaseMethod):
    name = "CM Bifid"
    description = "Modified Bifid cipher using Polybius square with a period"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "CM"
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        square = []
        used = set()
        for ch in key.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                square.append(ch)
        for ch in alphabet:
            if ch not in used:
                square.append(ch)

        def pos(ch):
            if ch == 'J':
                ch = 'I'
            idx = square.index(ch)
            return idx // 5, idx % 5

        letters = [c.upper() for c in text if c.isalpha()]
        letters = ['I' if c == 'J' else c for c in letters]

        period = 5
        result = []
        for start in range(0, len(letters), period):
            chunk = letters[start:start + period]
            rows = []
            cols = []
            for ch in chunk:
                r, c = pos(ch)
                rows.append(r)
                cols.append(c)
            interlaced = []
            for i in range(len(chunk)):
                interlaced.append(rows[i])
                interlaced.append(cols[i])
            for i in range(0, len(interlaced), 2):
                result.append(square[interlaced[i] * 5 + interlaced[i + 1]])

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
