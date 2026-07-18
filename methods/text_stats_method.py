from methods.base import BaseMethod


class TextStatsMethod(BaseMethod):
    name = "Text Stats"
    description = "Summarizes chars/words/bytes as a compact stamp"
    category = "Custom"

    def encode(self, text: str) -> str:
        char_count = len(text)
        word_count = len(text.split())
        byte_count = len(text.encode("utf-8"))
        return f"chars={char_count} words={word_count} bytes={byte_count}"
