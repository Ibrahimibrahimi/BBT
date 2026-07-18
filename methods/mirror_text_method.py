from methods.base import BaseMethod

class MirrorTextMethod(BaseMethod):
    name = "Mirror Text"
    description = "Reverse each word's characters"
    category = "Other"

    def encode(self, text: str) -> str:
        return ' '.join(word[::-1] for word in text.split(' '))
