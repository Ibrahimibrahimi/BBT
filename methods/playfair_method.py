from methods.base import BaseMethod

class PlayfairMethod(BaseMethod):
    name = "Playfair"
    description = "Digraph substitution cipher using a 5x5 square"
    category = "Cipher"

    def _make_square(self, keyword):
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        square = []
        used = set()
        for ch in keyword.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                square.append(ch)
        for ch in alphabet:
            if ch not in used:
                square.append(ch)
        return square

    def encode(self, text: str) -> str:
        square = self._make_square("PLAYFAIR")

        def pos(ch):
            if ch == 'J':
                ch = 'I'
            idx = square.index(ch)
            return idx // 5, idx % 5

        letters = [ch.upper() for ch in text if ch.isalpha()]
        digraphs = []
        i = 0
        while i < len(letters):
            a = letters[i]
            if i + 1 < len(letters) and letters[i + 1] != a:
                b = letters[i + 1]
                i += 2
            else:
                b = 'X'
                i += 1
            digraphs.append((a, b))

        result = ""
        for a, b in digraphs:
            r1, c1 = pos(a)
            r2, c2 = pos(b)
            if r1 == r2:
                result += square[r1 * 5 + (c1 + 1) % 5]
                result += square[r2 * 5 + (c2 + 1) % 5]
            elif c1 == c2:
                result += square[((r1 + 1) % 5) * 5 + c1]
                result += square[((r2 + 1) % 5) * 5 + c2]
            else:
                result += square[r1 * 5 + c2]
                result += square[r2 * 5 + c1]

        idx = 0
        out = ""
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
