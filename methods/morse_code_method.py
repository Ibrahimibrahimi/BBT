from methods.base import BaseMethod


class MorseCodeMethod(BaseMethod):
    name = "Morse Code"
    description = "Converts text to International Morse code"
    category = "Custom"

    TABLE = {
        "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".",
        "f": "..-.", "g": "--.", "h": "....", "i": "..", "j": ".---",
        "k": "-.-", "l": ".-..", "m": "--", "n": "-.", "o": "---",
        "p": ".--.", "q": "--.-", "r": ".-.", "s": "...", "t": "-",
        "u": "..-", "v": "...-", "w": ".--", "x": "-..-", "y": "-.--",
        "z": "--..",
        "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
        "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    }

    def encode(self, text: str) -> str:
        parts = []
        for ch in text:
            lower = ch.lower()
            if lower in self.TABLE:
                parts.append(self.TABLE[lower])
            elif ch == " ":
                parts.append("/")
            else:
                parts.append(ch)
        return " ".join(parts)
