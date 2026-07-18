from methods.base import BaseMethod

class SignMagnitudeMethod(BaseMethod):
    name = "Sign-Magnitude"
    description = "Sign bit + magnitude"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num < -127 or num > 127:
            return text
        sign = '1' if num < 0 else '0'
        mag = format(abs(num), '07b')
        return sign + mag
