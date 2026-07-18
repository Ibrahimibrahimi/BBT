from methods.base import BaseMethod

FLAG_MAP = {
    'A': '🚩', 'B': '🏳️', 'C': '🏁', 'D': '🏴', 'E': '🚩',
    'F': '🏳️', 'G': '🏁', 'H': '🏴', 'I': '🚩', 'J': '🏳️',
    'K': '🏁', 'L': '🏴', 'M': '🚩', 'N': '🏳️', 'O': '🏁',
    'P': '🏴', 'Q': '🚩', 'R': '🏳️', 'S': '🏁', 'T': '🏴',
    'U': '🚩', 'V': '🏳️', 'W': '🏁', 'X': '🏴', 'Y': '🚩',
    'Z': '🏳️',
}

ANGLE_MAP = {
    'A': '⬆️', 'B': '↗️', 'C': '➡️', 'D': '↘️', 'E': '⬇️',
    'F': '↙️', 'G': '⬅️', 'H': '↖️', 'I': '⬆️', 'J': '↗️',
    'K': '➡️', 'L': '↘️', 'M': '⬇️', 'N': '↙️', 'O': '⬅️',
    'P': '↖️', 'Q': '⬆️', 'R': '↗️', 'S': '➡️', 'T': '↘️',
    'U': '⬇️', 'V': '↙️', 'W': '⬅️', 'X': '↖️', 'Y': '⬆️',
    'Z': '↗️',
}


class FlagSemaphoreMethod(BaseMethod):
    name = "Flag Semaphore"
    description = "Letter-to-flag emoji mapping"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text.upper():
            if ch in FLAG_MAP:
                result.append(FLAG_MAP[ch] + ANGLE_MAP[ch])
            else:
                result.append(ch)
        return "".join(result)
