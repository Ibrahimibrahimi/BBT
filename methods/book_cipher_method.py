from methods.base import BaseMethod


class BookCipherMethod(BaseMethod):
    name = "Book Cipher"
    description = "Book Cipher: map words to numbers based on a key phrase"
    category = "Cipher"

    def encode(self, text: str) -> str:
        reference = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        ref_words = reference.upper().split()

        word_map = {}
        for i, word in enumerate(ref_words):
            word_map[word] = i + 1

        words = text.upper().split()
        result = []
        for word in words:
            if word in word_map:
                result.append(str(word_map[word]))
            else:
                result.append(word)

        return " ".join(result)
