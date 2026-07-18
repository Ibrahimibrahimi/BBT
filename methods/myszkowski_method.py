from methods.base import BaseMethod


class MyszkowskiMethod(BaseMethod):
    name = "Myszkowski"
    description = "Myszkowski cipher: Vigenere variant with repeated key letters grouped"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "KEY"
        clean = [c.upper() for c in text if c.isalpha()]
        key_upper = key.upper()

        groups = {}
        for i, k in enumerate(key_upper):
            if k not in groups:
                groups[k] = []
            groups[k].append(i)

        result = list(clean)
        for k, positions in groups.items():
            shift = ord(k) - ord('A')
            for pos in positions:
                i = pos
                while i < len(clean):
                    result[i] = chr((ord(clean[i]) - ord('A') + shift) % 26 + ord('A'))
                    i += len(key_upper)

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
