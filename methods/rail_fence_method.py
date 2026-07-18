from methods.base import BaseMethod


class RailFenceMethod(BaseMethod):
    name = "Rail Fence"
    description = "Rail fence transposition cipher, 3 rails"
    category = "Cipher"

    RAILS = 3

    def encode(self, text: str) -> str:
        if self.RAILS < 2 or not text:
            return text

        fence = [[] for _ in range(self.RAILS)]
        rail = 0
        direction = 1

        for ch in text:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == self.RAILS - 1:
                direction = -1
            rail += direction

        return "".join("".join(row) for row in fence)
