import re
from methods.base import BaseMethod

class SnakeCaseMethod(BaseMethod):
    name = "Snake Case"
    description = "Split on non-alphanumeric, join with underscores"
    category = "Other"

    def encode(self, text: str) -> str:
        words = re.findall(r'[a-zA-Z0-9]+', text)
        return '_'.join(w.lower() for w in words)
