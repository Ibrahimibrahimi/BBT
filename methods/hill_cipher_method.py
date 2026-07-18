from methods.base import BaseMethod

KEY_MATRIX = [[3, 3], [2, 5]]


class HillCipherMethod(BaseMethod):
    name = "Hill Cipher"
    description = "2x2 matrix multiplication cipher (key=[[3,3],[2,5]])"
    category = "Cipher"

    def encode(self, text: str) -> str:
        text = text.upper().replace(" ", "")
        if len(text) % 2 != 0:
            text += 'X'

        result = []
        for i in range(0, len(text), 2):
            a = ord(text[i]) - ord('A')
            b = ord(text[i + 1]) - ord('A')
            c0 = (KEY_MATRIX[0][0] * a + KEY_MATRIX[0][1] * b) % 26
            c1 = (KEY_MATRIX[1][0] * a + KEY_MATRIX[1][1] * b) % 26
            result.append(chr(c0 + ord('A')))
            result.append(chr(c1 + ord('A')))
        return "".join(result)
