from methods.base import BaseMethod


class DigrafidMethod(BaseMethod):
    name = "Digrafid"
    description = "Digrafid cipher using 3 Polybius squares and a key"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "KEY"
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
        sq2 = make_square(key.upper()[::-1] + "ABC")
        sq3 = make_square(key + "XYZ")

        def find(sq, ch):
            if ch == 'J':
                ch = 'I'
            idx = sq.index(ch)
            return idx // 5, idx % 5

        letters = [c.upper() for c in text if c.isalpha()]
        letters = ['I' if c == 'J' else c for c in letters]

        triads = []
        for i in range(0, len(letters), 2):
            if i + 1 < len(letters):
                r1, c1 = find(sq1, letters[i])
                r2, c2 = find(sq2, letters[i + 1])
                triads.append((r1, c1, r2, c2))
            else:
                r1, c1 = find(sq1, letters[i])
                triads.append((r1, c1, 0, 0))

        result = []
        for r1, c1, r2, c2 in triads:
            key_digit = r1 * 5 + c1
            result.append(str(key_digit + 1) if key_digit < 10 else str(key_digit + 1))
            result.append(str(r2 * 5 + c2 + 1))

        return "".join(result)
