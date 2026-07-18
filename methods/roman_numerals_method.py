from methods.base import BaseMethod

class RomanNumeralsMethod(BaseMethod):
    name = "Roman Numerals"
    description = "Convert to Roman numerals"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text)
        except ValueError:
            return text
        vals = [(1000,'M'),(900,'CM'),(500,'D'),(400,'CD'),(100,'C'),(90,'XC'),(50,'L'),(40,'XL'),(10,'X'),(9,'IX'),(5,'V'),(4,'IV'),(1,'I')]
        result = ''
        for val, sym in vals:
            while num >= val:
                result += sym
                num -= val
        return result or text
