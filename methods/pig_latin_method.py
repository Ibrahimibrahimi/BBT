from methods.base import BaseMethod


class PigLatinMethod(BaseMethod):
    name = "Pig Latin"
    description = "Pig Latin, English word transformation"
    category = "Other"

    _vowels = "aeiouAEIOU"

    def encode(self, text: str) -> str:
        words = text.split(" ")
        result = []
        for word in words:
            if not word:
                result.append(word)
                continue
            if word[0] in self._vowels:
                result.append(word + "way")
            else:
                idx = 0
                for i, ch in enumerate(word):
                    if ch in self._vowels:
                        idx = i
                        break
                else:
                    idx = len(word)
                result.append(word[idx:] + word[:idx] + "ay")
        return " ".join(result)
