from methods.base import BaseMethod

class MetaphoneMethod(BaseMethod):
    name = "Metaphone"
    description = "Lawrence Philips' Metaphone algorithm"
    category = "Other"

    def encode(self, text: str) -> str:
        if not text:
            return ""
        text = text.upper()
        result = ""
        i = 0
        while i < len(text) and len(result) < 6:
            c = text[i]
            nc = text[i + 1] if i + 1 < len(text) else ''
            if c in 'AEIOU':
                if i == 0:
                    result += c
                i += 1
            elif c == 'B':
                if i == 0 or text[i - 1] != 'M':
                    result += 'B'
                i += 1
            elif c == 'C':
                if nc in 'EIY':
                    result += 'S'
                else:
                    result += 'K'
                i += 1
            elif c == 'D':
                if nc in 'GC':
                    result += 'J'
                    i += 2
                else:
                    result += 'T'
                    i += 1
            elif c in 'FJ':
                result += c
                i += 1
            elif c == 'G':
                if nc in 'EIY':
                    i += 1
                elif i > 0 and text[i - 1] not in 'HN':
                    result += 'K'
                    i += 1
                else:
                    i += 1
            elif c == 'H':
                if i == 0 or text[i - 1] not in 'AEIOU':
                    if nc in 'AEIOU':
                        result += 'H'
                i += 1
            elif c in 'JKLMNR':
                result += c if c != 'J' else 'J'
                i += 1
            elif c == 'P':
                if i + 1 < len(text) and text[i + 1] == 'H':
                    result += 'F'
                    i += 2
                else:
                    result += 'P'
                    i += 1
            elif c == 'Q':
                result += 'K'
                i += 1
            elif c == 'S':
                if nc == 'H':
                    result += 'X'
                    i += 2
                elif nc in 'IAEIY':
                    result += 'S'
                    i += 1
                else:
                    result += 'S'
                    i += 1
            elif c == 'T':
                if nc == 'H':
                    result += '0'
                    i += 2
                elif nc in 'IAEIY':
                    result += 'X'
                    i += 1
                else:
                    result += 'T'
                    i += 1
            elif c == 'V':
                result += 'F'
                i += 1
            elif c in 'WY':
                if nc in 'AEIOU':
                    result += c
                i += 1
            elif c == 'X':
                result += 'KS'
                i += 1
            elif c == 'Z':
                result += 'S'
                i += 1
            else:
                i += 1
        return result
