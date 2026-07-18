from methods.base import BaseMethod

class BifidMethod(BaseMethod):
    name = "Bifid"
    description = "Polybius-based fractionation cipher"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "KEYWORD"
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
            idx = square.index(ch)
            return idx // 5, idx % 5

        letters = [ch.upper() for ch in text if ch.isalpha()]
        rows = []
        cols = []
        for ch in letters:
            if ch == 'J':
                ch = 'I'
            r, c = pos(ch)
            rows.append(r)
            cols.append(c)

        combined = rows + cols
        result = ""
        for i in range(0, len(combined), 2):
            r = combined[i]
            c = combined[i + 1]
            result += square[r * 5 + c]

        idx = 0
        out = ""
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
