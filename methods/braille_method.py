from methods.base import BaseMethod


class BrailleMethod(BaseMethod):
    name = "Braille"
    description = "Maps a-z to Unicode Braille pattern characters"
    category = "Custom"

    TABLE = {
        "a": "\u2801", "b": "\u2803", "c": "\u2809", "d": "\u2819", "e": "\u2811",
        "f": "\u280b", "g": "\u281b", "h": "\u2813", "i": "\u280a", "j": "\u281a",
        "k": "\u2805", "l": "\u2807", "m": "\u280d", "n": "\u281d", "o": "\u2815",
        "p": "\u280f", "q": "\u281f", "r": "\u2817", "s": "\u280e", "t": "\u281e",
        "u": "\u2825", "v": "\u2827", "w": "\u283a", "x": "\u282d", "y": "\u283d",
        "z": "\u2835",
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in self.TABLE:
                result.append(self.TABLE[lower])
            elif ch == " ":
                result.append("\u2800")
            else:
                result.append(ch)
        return "".join(result)
