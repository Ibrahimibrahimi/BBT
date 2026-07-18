from methods.base import BaseMethod


class InterruptedKeyMethod(BaseMethod):
    name = "Interrupted Key"
    description = "Interrupted Key cipher: Vigenere with interrupted key"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "INTERRUPTEDKEY"
        key_upper = key.upper()
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        letters = [c.upper() for c in text if c.isalpha()]
        result = []
        key_idx = 0
        for i, ch in enumerate(letters):
            if i % 5 == 0 and i > 0:
                key_idx = 0
            shift = ord(key_upper[key_idx % len(key_upper)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            key_idx += 1

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
