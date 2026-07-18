from methods.base import BaseMethod


class PolluxMethod(BaseMethod):
    name = "Pollux"
    description = "Pollux cipher: fractionated Morse with numeric substitution"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "POLLUX"
        morse_map = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', ' ': ' '
        }

        substitution = {}
        used = set()
        for ch in "0123456789":
            substitution[ch] = ch
        for ch in key:
            if ch not in used:
                substitution[ch] = str(len(substitution) % 10)
                used.add(ch)

        morse_str = ""
        for ch in text.upper():
            if ch in morse_map:
                morse_str += morse_map[ch] + "X"

        result = []
        for c in morse_str:
            if c in substitution:
                result.append(substitution[c])
            elif c == '.':
                result.append('1')
            elif c == '-':
                result.append('2')
            else:
                result.append('3')

        return "".join(result)
