from methods.base import BaseMethod

class DoubleMetaphoneMethod(BaseMethod):
    name = "Double Metaphone"
    description = "Returns primary and secondary codes"
    category = "Other"

    def encode(self, text: str) -> str:
        if not text:
            return ""
        text = text.upper()
        primary = ""
        secondary = ""
        i = 0
        while i < len(text) and len(primary) < 6:
            c = text[i]
            nc = text[i + 1] if i + 1 < len(text) else ''
            if c in 'AEIOU':
                if i == 0:
                    primary += c
                    secondary += c
                i += 1
            elif c == 'B':
                if i > 0 and text[i - 1] == 'M':
                    i += 1
                else:
                    primary += 'B'
                    secondary += 'B'
                    i += 1
            elif c == 'C':
                if nc in 'EIY':
                    primary += 'S'
                    secondary += 'S'
                elif nc == 'H':
                    primary += 'X'
                    secondary += 'X'
                    i += 1
                else:
                    primary += 'K'
                    secondary += 'K'
                i += 1
            elif c == 'D':
                if nc in 'GC':
                    primary += 'J'
                    secondary += 'J'
                    i += 2
                else:
                    primary += 'T'
                    secondary += 'T'
                    i += 1
            elif c in 'FJ':
                primary += c
                secondary += c
                i += 1
            elif c == 'G':
                if nc in 'EIY':
                    if i > 0 and text[i - 1] == 'G':
                        primary += 'K'
                        secondary += 'K'
                    else:
                        primary += 'J'
                        secondary += 'J'
                else:
                    primary += 'K'
                    secondary += 'K'
                i += 1
            elif c == 'H':
                if i == 0 or text[i - 1] not in 'AEIOU':
                    if nc in 'AEIOU':
                        primary += 'H'
                        secondary += 'H'
                i += 1
            elif c in 'JKLMNR':
                primary += c
                secondary += c
                i += 1
            elif c == 'P':
                if nc == 'H':
                    primary += 'F'
                    secondary += 'F'
                    i += 2
                else:
                    primary += 'P'
                    secondary += 'P'
                    i += 1
            elif c == 'Q':
                primary += 'K'
                secondary += 'K'
                i += 1
            elif c == 'S':
                if nc == 'H' or (nc == 'I' and i + 2 < len(text) and text[i + 2] in 'AO'):
                    primary += 'X'
                    secondary += 'X'
                    if nc == 'H':
                        i += 2
                    else:
                        i += 1
                else:
                    primary += 'S'
                    secondary += 'S'
                    i += 1
            elif c == 'T':
                if nc == 'H':
                    primary += '0'
                    secondary += '0'
                    i += 2
                elif nc in 'IAEIY':
                    primary += 'X'
                    secondary += 'X'
                    i += 1
                else:
                    primary += 'T'
                    secondary += 'T'
                    i += 1
            elif c == 'V':
                primary += 'F'
                secondary += 'F'
                i += 1
            elif c in 'WY':
                if nc in 'AEIOU':
                    primary += c
                    secondary += c
                i += 1
            elif c == 'X':
                primary += 'KS'
                secondary += 'KS'
                i += 1
            elif c == 'Z':
                primary += 'S'
                secondary += 'S'
                i += 1
            else:
                i += 1
        if not secondary:
            secondary = primary
        return f"{primary}/{secondary}"
