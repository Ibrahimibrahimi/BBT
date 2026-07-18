from methods.base import BaseMethod


class GromarkMethod(BaseMethod):
    name = "Gromark"
    description = "Gromark cipher: running key with keyword and number"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "GROMARK"
        number = "57392"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        primer = ""
        used = set()
        for ch in keyword.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                primer += ch
        for ch in alphabet:
            if ch not in used:
                primer += ch

        running_key = primer + number + primer

        letters = [c.upper() for c in text if c.isalpha()]
        result = []
        for i, ch in enumerate(letters):
            if i < len(running_key):
                shift = int(running_key[i]) if running_key[i].isdigit() else ord(running_key[i]) - ord('A')
            else:
                shift = i % 26
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
