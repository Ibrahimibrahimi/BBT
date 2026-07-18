from methods.base import BaseMethod


class TwoSquareMethod(BaseMethod):
    name = "Two-Square"
    description = "Two-Square cipher: uses two Polybius squares for digraph substitution"
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
        sq1 = self._make_square("CIPHER")
        sq2 = self._make_square("KEYWORD")

        def find(sq, ch):
            if ch == 'J':
                ch = 'I'
            idx = sq.index(ch)
            return idx // 5, idx % 5

        letters = [ch.upper() for ch in text if ch.isalpha()]
        letters = ['I' if c == 'J' else c for c in letters]

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
            r1, c1 = find(sq1, a)
            r2, c2 = find(sq2, b)
            result += sq1[r1 * 5 + c2]
            result += sq2[r2 * 5 + c1]

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
