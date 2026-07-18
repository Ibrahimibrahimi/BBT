from methods.base import BaseMethod


class ProgressiveKeyMethod(BaseMethod):
    name = "Progressive Key"
    description = "Progressive Key cipher: Vigenere with key that shifts each round"
    category = "Cipher"

    def encode(self, text: str) -> str:
        base_key = "PROGRESSIVE"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        letters = [c.upper() for c in text if c.isalpha()]
        key_upper = base_key.upper()

        result = []
        for i, ch in enumerate(letters):
            key_char_idx = i % len(key_upper)
            shift = (ord(key_upper[key_char_idx]) - ord('A') + i // len(key_upper)) % 26
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
