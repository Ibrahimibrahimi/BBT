from methods.base import BaseMethod


class SeriatedPlayfairMethod(BaseMethod):
    name = "Seriated Playfair"
    description = "Modified Playfair with periodic keying"
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
        key = "SERIATED"
        square = self._make_square(key)
        period = 6

        def pos(ch):
            if ch == 'J':
                ch = 'I'
            idx = square.index(ch)
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
        for idx, (a, b) in enumerate(digraphs):
            if idx % period == 0 and idx > 0:
                shift = (idx // period) % 26
                temp_sq = square[shift:] + square[:shift]
            else:
                temp_sq = square

            r1, c1 = pos(a)
            r2, c2 = pos(b)
            if r1 == r2:
                result += temp_sq[r1 * 5 + (c1 + 1) % 5]
                result += temp_sq[r2 * 5 + (c2 + 1) % 5]
            elif c1 == c2:
                result += temp_sq[((r1 + 1) % 5) * 5 + c1]
                result += temp_sq[((r2 + 1) % 5) * 5 + c2]
            else:
                result += temp_sq[r1 * 5 + c2]
                result += temp_sq[r2 * 5 + c1]

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
