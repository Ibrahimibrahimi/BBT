from methods.base import BaseMethod

class KeywordMethod(BaseMethod):
    name = "Keyword"
    description = "Keyword-based substitution cipher using 'CRYPTER'"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "CRYPTER"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        cipher = []
        used = set()
        for ch in keyword:
            if ch not in used:
                used.add(ch)
                cipher.append(ch)
        for ch in alphabet:
            if ch not in used:
                cipher.append(ch)

        mapping = {}
        for i, ch in enumerate(alphabet):
            mapping[ch] = cipher[i]

        result = ""
        for ch in text:
            if ch.isalpha():
                base = 'A' if ch.isupper() else 'a'
                mapped = mapping[ch.upper()]
                result += mapped.lower() if ch.islower() else mapped
            else:
                result += ch
        return result
