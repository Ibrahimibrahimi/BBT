import re
from methods.base import BaseMethod

class CamelCaseMethod(BaseMethod):
    name = "CamelCase"
    description = "Split on non-alphanumeric, join with capitalization"
    category = "Other"

    def encode(self, text: str) -> str:
        words = re.findall(r'[a-zA-Z0-9]+', text)
        if not words:
            return text
        result = words[0].lower()
        for word in words[1:]:
            result += word.capitalize()
        return result
