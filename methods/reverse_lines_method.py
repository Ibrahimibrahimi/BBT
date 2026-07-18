from methods.base import BaseMethod

class ReverseLinesMethod(BaseMethod):
    name = "Reverse Lines"
    description = "Reverse line order"
    category = "Other"

    def encode(self, text: str) -> str:
        return '\n'.join(reversed(text.split('\n')))
