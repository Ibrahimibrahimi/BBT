from methods.base import BaseMethod

BOARD = {
    'T': '0', 'A': '1', 'N': '2', 'E': '3',
    ' ': '4',
    'I': '5', 'R': '6', 'O': '7',
    'S': '81', 'B': '82', 'C': '83', 'D': '84', 'E': '85',
    'F': '86', 'G': '87', 'H': '88', 'J': '89',
    'K': '91', 'L': '92', 'M': '93', 'P': '94',
    'Q': '95', 'U': '96', 'V': '97', 'W': '98',
    'X': '99', 'Y': '90', 'Z': '9!',
    'F': '86', 'G': '87', 'H': '88', 'J': '89',
}

BOARD = {}
_single = "TANEIRO"
for i, ch in enumerate(_single):
    BOARD[ch] = str(i)
BOARD[' '] = '4'

_double = "SBCDFGHJKLMPQUVWXYZ"
for i, ch in enumerate(_double):
    BOARD[ch] = '8' + str(i) if i < 10 else '9' + str(i - 10)


class StraddleCheckerboardMethod(BaseMethod):
    name = "Straddle Checkerboard"
    description = "Converts letters to numeric output using straddle checkerboard"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = []
        for ch in text.upper():
            if ch in BOARD:
                result.append(BOARD[ch])
            elif ch.isdigit():
                result.append(ch)
        return "".join(result)
