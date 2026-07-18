from methods.base import BaseMethod

MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', ' ': '/',
}

MORSE_SEP = 'X'
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#"
TRIGRAMS = [CHARS[i:i+3] for i in range(0, len(CHARS), 3)]

TRIGRAM_LOOKUP = {}
for i, t in enumerate(TRIGRAMS):
    TRIGRAM_LOOKUP[t] = i


class FractionatedMorseMethod(BaseMethod):
    name = "Fractionated Morse"
    description = "Morse code fractionated into trigrams via keyword substitution"
    category = "Cipher"

    def encode(self, text: str) -> str:
        morse_parts = []
        for ch in text.upper():
            if ch in MORSE:
                morse_parts.append(MORSE[ch])
        raw = MORSE_SEP.join(morse_parts)

        remainder = len(raw) % 3
        if remainder != 0:
            raw += '.' * (3 - remainder)

        result = []
        for i in range(0, len(raw), 3):
            trig = raw[i:i+3]
            dots = trig.count('.')
            dashes = trig.count('-')
            idx = min(dashes * 6 + dots, len(TRIGRAMS) - 1)
            result.append(TRIGRAMS[idx])
        return "".join(result)
