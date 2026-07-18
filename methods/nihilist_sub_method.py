from methods.base import BaseMethod


class NihilistSubMethod(BaseMethod):
    name = "Nihilist Substitution"
    description = "Nihilist Substitution: Polybius square with numeric key addition"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "Nihilist"
        key_vals = [44, 45, 23, 15, 34, 44, 15, 45]

        SQUARE_LETTERS = []
        for ch in keyword:
            if ch.upper() not in SQUARE_LETTERS:
                SQUARE_LETTERS.append(ch.upper())
        for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if ch not in SQUARE_LETTERS:
                SQUARE_LETTERS.append(ch)

        LOOKUP = {}
        for r in range(5):
            for c in range(5):
                LOOKUP[SQUARE_LETTERS[r * 5 + c]] = (r + 1) * 10 + (c + 1)

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
