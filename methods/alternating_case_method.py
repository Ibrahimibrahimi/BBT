from methods.base import BaseMethod


class AlternatingCaseMethod(BaseMethod):
    name = "Alternating Case"
    description = "aLtErNaTiNg CaSe, sometimes called 'mocking spongebob' text"
    category = "Custom"

    def encode(self, text: str) -> str:
        result = []
        upper = False
        for ch in text:
            if ch.isalpha():
                result.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                result.append(ch)
        return "".join(result)
