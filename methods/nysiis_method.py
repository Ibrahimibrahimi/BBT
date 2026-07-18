from methods.base import BaseMethod

class NysiisMethod(BaseMethod):
    name = "NYSIIS"
    description = "New York State Identification and Intelligence System"
    category = "Other"

    def encode(self, text: str) -> str:
        if not text:
            return ""
        text = text.upper()
        result = text[0]
        prev = text[0]
        i = 1
        while i < len(text) and len(result) < 14:
            c = text[i]
            nc = text[i + 1] if i + 1 < len(text) else ''
            if c == 'A':
                result += 'A'
            elif c == 'B':
                result += 'P'
            elif c == 'C':
                result += 'S'
            elif c == 'D':
                result += 'T'
            elif c == 'E':
                result += 'A'
            elif c == 'F':
                result += 'P'
            elif c == 'G':
                result += 'K'
            elif c == 'H':
                if nc not in 'AEIOU':
                    result += 'A'
                i += 1
                continue
            elif c == 'I':
                result += 'A'
            elif c == 'J':
                result += 'J'
            elif c == 'K':
                result += 'C'
            elif c == 'L':
                result += 'L'
            elif c == 'M':
                result += 'N'
            elif c == 'N':
                result += 'N'
            elif c == 'O':
                result += 'O'
            elif c == 'P':
                result += 'P'
            elif c == 'Q':
                result += 'C'
            elif c == 'R':
                result += 'R'
            elif c == 'S':
                result += 'S'
            elif c == 'T':
                result += 'T'
            elif c == 'U':
                result += 'A'
            elif c == 'V':
                result += 'P'
            elif c == 'W':
                result += 'W'
            elif c == 'X':
                result += 'C'
            elif c == 'Y':
                result += 'Y'
            elif c == 'Z':
                result += 'S'
            prev = c
            i += 1
        if result.endswith('S'):
            result = result[:-1]
        if result.endswith('A'):
            result = result[:-1]
        return result
