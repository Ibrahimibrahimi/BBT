from methods.base import BaseMethod


class NATOPhoneticMethod(BaseMethod):
    name = "NATO Phonetic"
    description = "Spells out letters using the NATO phonetic alphabet"
    category = "Custom"

    ALPHABET = {
        "a": "Alfa", "b": "Bravo", "c": "Charlie", "d": "Delta", "e": "Echo",
        "f": "Foxtrot", "g": "Golf", "h": "Hotel", "i": "India", "j": "Juliett",
        "k": "Kilo", "l": "Lima", "m": "Mike", "n": "November", "o": "Oscar",
        "p": "Papa", "q": "Quebec", "r": "Romeo", "s": "Sierra", "t": "Tango",
        "u": "Uniform", "v": "Victor", "w": "Whiskey", "x": "X-ray", "y": "Yankee",
        "z": "Zulu",
    }

    def encode(self, text: str) -> str:
        words = []
        for ch in text:
            lower = ch.lower()
            if lower in self.ALPHABET:
                words.append(self.ALPHABET[lower])
            elif ch == " ":
                words.append("/")
            elif ch.isdigit():
                words.append(ch)
            else:
                words.append(ch)
        return " ".join(words)
