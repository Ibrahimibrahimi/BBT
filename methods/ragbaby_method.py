from methods.base import BaseMethod


class RagbabyMethod(BaseMethod):
    name = "Ragbaby"
    description = "Ragbaby cipher: keyword-based with position-based shifts"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "RAGBABY"
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

        cipher_alphabet = ""
        used = set()
        for ch in keyword.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                cipher_alphabet += ch
        for ch in alphabet:
            if ch not in used:
                cipher_alphabet += ch

        mapping = dict(zip(alphabet, cipher_alphabet))

        words = text.upper().split()
        result_words = []
        for word in words:
            letters = [c for c in word if c.isalpha()]
            shifted = []
            for i, ch in enumerate(letters):
                if ch in mapping:
                    base_idx = alphabet.index(ch)
                    shift = (i + 1) % 26
                    shifted.append(alphabet[(base_idx + shift) % 26])
                else:
                    shifted.append(ch)
            result_words.append("".join(shifted))

        out = ""
        word_idx = 0
        for ch in text:
            if ch == ' ':
                out += ' '
            elif ch.isalpha():
                if word_idx < len(result_words):
                    word = result_words[word_idx]
                    for wc in word:
                        out += wc
                    word_idx += 1
            else:
                out += ch
        return out
