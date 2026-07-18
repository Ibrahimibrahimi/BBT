from methods.base import BaseMethod


class MonomeDinomeMethod(BaseMethod):
    name = "Monome-Dinome"
    description = "Monome-Dinome cipher: uses single and double digit codes"
    category = "Cipher"

    def encode(self, text: str) -> str:
        mapping = {
            'A': '1', 'B': '2', 'C': '3', 'D': '4', 'E': '5',
            'F': '11', 'G': '12', 'H': '13', 'I': '14', 'J': '15',
            'K': '21', 'L': '22', 'M': '23', 'N': '24', 'O': '25',
            'P': '31', 'Q': '32', 'R': '33', 'S': '34', 'T': '35',
            'U': '41', 'V': '42', 'W': '43', 'X': '44', 'Y': '45',
            'Z': '51'
        }

        result = []
        for ch in text.upper():
            if ch in mapping:
                result.append(mapping[ch])
            else:
                result.append(ch)

        return "".join(result)
