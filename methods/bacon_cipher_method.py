from methods.base import BaseMethod

class BaconCipherMethod(BaseMethod):
    name = "Bacon Cipher"
    description = "Encode letters as 5-bit binary using a/b"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                val = ord(ch.upper()) - ord('A')
                bits = format(val, '05b')
                result += bits.replace('0', 'a').replace('1', 'b')
            else:
                result += ch
        return result
