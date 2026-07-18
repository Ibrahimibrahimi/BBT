from methods.base import BaseMethod


class WordCountMethod(BaseMethod):
    name = "Word Count"
    description = "Word Count, output words=N chars=N lines=N"
    category = "Other"

    def encode(self, text: str) -> str:
        words = len(text.split()) if text.strip() else 0
        chars = len(text)
        lines = text.count('\n') + 1
        return f"words={words} chars={chars} lines={lines}"
