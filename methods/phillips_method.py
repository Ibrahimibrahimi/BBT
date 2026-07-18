from methods.base import BaseMethod


class PhillipsMethod(BaseMethod):
    name = "Phillips"
    description = "Phillips cipher using two 5x5 squares"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "PHILLIPS"
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

        def make_square(kw):
            sq = []
            used = set()
            for ch in kw.upper():
                if ch not in used and ch in alphabet:
                    used.add(ch)
                    sq.append(ch)
            for ch in alphabet:
                if ch not in used:
                    sq.append(ch)
            return sq

        sq1 = make_square(key)
        sq2 = make_square(key[::-1] + "ABCDEF")

        def find(sq, ch):
            if ch == 'J':
                ch = 'I'
            idx = sq.index(ch)
            return idx // 5, idx % 5

        letters = [c.upper() for c in text if c.isalpha()]
        letters = ['I' if c == 'J' else c for c in letters]

        result = []
        for i in range(0, len(letters), 2):
            if i + 1 < len(letters):
                r1, c1 = find(sq1, letters[i])
                r2, c2 = find(sq2, letters[i + 1])
                if r1 == r2:
                    result.append(sq1[r1 * 5 + (c1 + 1) % 5])
                    result.append(sq2[r2 * 5 + (c2 + 1) % 5])
                elif c1 == c2:
                    result.append(sq1[((r1 + 1) % 5) * 5 + c1])
                    result.append(sq2[((r2 + 1) % 5) * 5 + c2])
                else:
                    result.append(sq1[r1 * 5 + c2])
                    result.append(sq2[r2 * 5 + c1])
            else:
                r1, c1 = find(sq1, letters[i])
                result.append(sq1[r1 * 5 + (c1 + 1) % 5])

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
