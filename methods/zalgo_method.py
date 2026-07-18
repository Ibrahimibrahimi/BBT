import random
from methods.base import BaseMethod

class ZalgoMethod(BaseMethod):
    name = "Zalgo"
    description = "Corrupts text with combining diacritical marks"
    category = "Other"

    def encode(self, text: str) -> str:
        above = [chr(c) for c in range(0x0300, 0x036F)]
        below = [chr(c) for c in range(0x0300, 0x036F)]
        random.seed(42)
        result = []
        for ch in text:
            result.append(ch)
            for _ in range(random.randint(2, 5)):
                result.append(random.choice(above))
            for _ in range(random.randint(2, 5)):
                result.append(random.choice(below))
        return ''.join(result)
