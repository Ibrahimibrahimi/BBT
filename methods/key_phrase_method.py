from methods.base import BaseMethod


class KeyPhraseMethod(BaseMethod):
    name = "Key Phrase"
    description = "Key Phrase cipher: keyword creates substitution alphabet"
    category = "Cipher"

    def encode(self, text: str) -> str:
        phrase = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        cipher = ""
        used = set()
        for ch in phrase.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                cipher += ch
        for ch in alphabet:
            if ch not in used:
                cipher += ch

        mapping = dict(zip(alphabet, cipher))
        result = []
        for ch in text.upper():
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
