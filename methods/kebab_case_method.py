import re
from methods.base import BaseMethod

class KebabCaseMethod(BaseMethod):
    name = "Kebab Case"
    description = "Split on non-alphanumeric, join with hyphens"
    category = "Other"

    def encode(self, text: str) -> str:
        words = re.findall(r'[a-zA-Z0-9]+', text)
        return '-'.join(w.lower() for w in words)
