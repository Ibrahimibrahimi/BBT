import math
from collections import Counter
from methods.base import BaseMethod


class EntropyMethod(BaseMethod):
    name = "Entropy"
    description = "Entropy, Shannon entropy of input text"
    category = "Other"

    def encode(self, text: str) -> str:
        if not text:
            return "entropy=0.000000"
        counts = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return f"entropy={entropy:.6f}"
