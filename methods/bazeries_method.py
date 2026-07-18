from methods.base import BaseMethod


class BazeriesMethod(BaseMethod):
    name = "Bazeries"
    description = "Bazeries cipher: transposition + substitution using a number and keyword"
    category = "Cipher"

    def encode(self, text: str) -> str:
        number = 123456
        keyword = "SECRET"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        num_str = str(number)
        digit_map = {}
        for i, d in enumerate(num_str):
            digit_map[d] = str(i + 1)

        shifted = ""
        used = set()
        for ch in keyword.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                shifted += ch
        for ch in alphabet:
            if ch not in used:
                shifted += ch

        shift = sum(int(d) for d in str(number)) % 26
        permuted = shifted[shift:] + shifted[:shift]

        mapping = dict(zip(alphabet, permuted))

        reversed_text = [c.upper() for c in text if c.isalpha()][::-1]
        result = []
        for ch in reversed_text:
            if ch in mapping:
                result.append(mapping[ch])
            else:
                result.append(ch)

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
