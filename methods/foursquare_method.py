from methods.base import BaseMethod

class FoursquareMethod(BaseMethod):
    name = "Four-Square"
    description = "Digraph substitution cipher using four 5x5 squares"
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
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        std_square = list(alphabet)
        key1 = self._make_square("CIPHER")
        key2 = self._make_square("METHOD")

        def pos(square, ch):
            if ch == 'J':
                ch = 'I'
            idx = square.index(ch)
            return idx // 5, idx % 5

        def lookup(square, row, col):
            return square[row * 5 + col]

        letters = [ch.upper() for ch in text if ch.isalpha()]
        if len(letters) % 2 != 0:
            letters.append('X')

        result = ""
        for i in range(0, len(letters), 2):
            r1, c1 = pos(std_square, letters[i])
            r2, c2 = pos(std_square, letters[i + 1])
            result += lookup(key1, r1, c2)
            result += lookup(key2, r2, c1)

        idx = 0
        out = ""
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
