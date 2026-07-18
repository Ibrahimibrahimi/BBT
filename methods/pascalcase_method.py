import re
from methods.base import BaseMethod

class PascalCaseMethod(BaseMethod):
    name = "PascalCase"
    description = "Like CamelCase but always starts capitalized"
    category = "Other"

    def encode(self, text: str) -> str:
        words = re.findall(r'[a-zA-Z0-9]+', text)
        return ''.join(w.capitalize() for w in words)
