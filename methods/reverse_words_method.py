from methods.base import BaseMethod

class ReverseWordsMethod(BaseMethod):
    name = "Reverse Words"
    description = "Reverse word order but keep characters"
    category = "Other"

    def encode(self, text: str) -> str:
        return ' '.join(reversed(text.split()))
