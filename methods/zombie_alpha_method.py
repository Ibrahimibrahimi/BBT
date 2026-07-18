from methods.base import BaseMethod


class ZombieAlphaMethod(BaseMethod):
    name = "Zombie Alpha"
    description = "Zombie Alpha, zombie-style letter spelling"
    category = "Other"

    _map = {
        'A': '@@', 'B': '8)', 'C': '(', 'D': '|)', 'E': '3',
        'F': '|=', 'G': '6', 'H': '#', 'I': '!', 'J': '_|',
        'K': '|<', 'L': '|_', 'M': '/\\/\\', 'N': '|\\|', 'O': '0',
        'P': '|*', 'Q': '(,)', 'R': '|2', 'S': '$', 'T': '+',
        'U': '|_|', 'V': '\\/', 'W': '\\^/', 'X': '><', 'Y': '`/',
        'Z': '2',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.upper() in self._map:
                mapped = self._map[ch.upper()]
                result.append(mapped if ch.isupper() else mapped.lower())
            else:
                result.append(ch)
        return "".join(result)
