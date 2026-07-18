from methods.base import BaseMethod


class MorbitMethod(BaseMethod):
    name = "Morbit"
    description = "Morbit cipher: fractionated Morse with numeric substitution"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "GROMARK"
        key_square = list(dict.fromkeys(key.upper() + "ABCDEFGHIJKL"))
        morse_map = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..'
        }

        morse_str = ""
        for ch in text.upper():
            if ch in morse_map:
                morse_str += morse_map[ch] + "X"

        groups = [morse_str[i:i+3] for i in range(0, len(morse_str), 3)]

        digit_map = {'.': '1', '-': '2', 'X': '3'}
        result = []
        for g in groups:
            numeric = ""
            for c in g:
                if c in digit_map:
                    numeric += digit_map[c]
                else:
                    numeric += "3"
            result.append(numeric)

        return "".join(result)
