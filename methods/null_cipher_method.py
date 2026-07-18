from methods.base import BaseMethod


class NullCipherMethod(BaseMethod):
    name = "Null"
    description = "Null cipher: encodes message as first letter of each word"
    category = "Cipher"

    def encode(self, text: str) -> str:
        words = text.split()
        result = []
        for word in words:
            if word and word[0].isalpha():
                result.append(word[0].upper())
            else:
                result.append(word)
        return " ".join(result)
