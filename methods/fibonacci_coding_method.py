from methods.base import BaseMethod

class FibonacciCodingMethod(BaseMethod):
    name = "Fibonacci Coding"
    description = "Represent as sum of Fibonacci numbers"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num <= 0:
            return text
        fibs = [1, 2]
        while fibs[-1] < num:
            fibs.append(fibs[-1] + fibs[-2])
        result = []
        remaining = num
        for f in reversed(fibs[:-1]):
            if f <= remaining:
                result.append('1')
                remaining -= f
            else:
                result.append('0')
        result.append('1')
        return ''.join(result)
