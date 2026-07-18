from methods.base import BaseMethod

class PortaMethod(BaseMethod):
    name = "Porta"
    description = "Polyalphabetic tabular cipher with keyword 'PORTA'"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "PORTA"

        def get_shift_table(letter):
            n = ord(letter.upper()) - ord('A')
            half = n // 2
            return [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12][half] if half < 13 else 0

        result = ""
        ki = 0
        for ch in text:
            if ch.isalpha():
                k_ch = keyword[ki % len(keyword)]
                shift = get_shift_table(k_ch)
                if ch.isupper():
                    result += chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(ch.upper()) - ord('A') + shift) % 26 + ord('a'))
                ki += 1
            else:
                result += ch
        return result
