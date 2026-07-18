from methods.base import BaseMethod

class BeiderMorseMethod(BaseMethod):
    name = "Beider-Morse"
    description = "Phonetic matching algorithm (simplified)"
    category = "Other"

    def encode(self, text: str) -> str:
        if not text:
            return ""
        text = text.lower()
        result = []
        i = 0
        while i < len(text):
            c = text[i]
            nc = text[i + 1] if i + 1 < len(text) else ''
            if c in 'aeiouy':
                result.append(c)
            elif c == 'b':
                result.append('b')
            elif c == 'c':
                if nc in 'eiy':
                    result.append('s')
                else:
                    result.append('k')
            elif c == 'd':
                result.append('d')
            elif c == 'f':
                result.append('f')
            elif c == 'g':
                result.append('g')
            elif c == 'h':
                if i == 0 or text[i - 1] not in 'aeiouy':
                    result.append('')
                else:
                    result.append('')
            elif c == 'j':
                result.append('dZ')
            elif c == 'k':
                result.append('k')
            elif c == 'l':
                result.append('l')
            elif c == 'm':
                result.append('m')
            elif c == 'n':
                result.append('n')
            elif c == 'p':
                result.append('p')
            elif c == 'q':
                result.append('k')
            elif c == 'r':
                result.append('r')
            elif c == 's':
                result.append('s')
            elif c == 't':
                result.append('t')
            elif c == 'v':
                result.append('v')
            elif c == 'w':
                result.append('v')
            elif c == 'x':
                result.append('ks')
            elif c == 'z':
                result.append('z')
            else:
                result.append(c)
            i += 1
        return ''.join(result)
