from methods.base import BaseMethod

PIGPEN = {
    'A': '\u2718', 'B': '\u2719', 'C': '\u271A', 'D': '\u271B', 'E': '\u271C',
    'F': '\u271D', 'G': '\u271E', 'H': '\u271F', 'I': '\u2720', 'J': '\u2721',
    'K': '\u2722', 'L': '\u2723', 'M': '\u2724', 'N': '\u2725', 'O': '\u2726',
    'P': '\u2727', 'Q': '\u2728', 'R': '\u2729', 'S': '\u272A', 'T': '\u272B',
    'U': '\u272C', 'V': '\u272D', 'W': '\u272E', 'X': '\u272F', 'Y': '\u2730',
    'Z': '\u2731'
}


class PigpenMethod(BaseMethod):
    name = "Pigpen"
    description = "Symbol substitution cipher using Unicode symbols"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text.upper():
            if ch in PIGPEN:
                result.append(PIGPEN[ch])
            else:
                result.append(ch)
        return "".join(result)
