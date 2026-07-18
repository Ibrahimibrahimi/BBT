from methods.base import BaseMethod


class RailFence7Method(BaseMethod):
    name = "Rail Fence (7 rails)"
    description = "Rail Fence cipher with 7 rails"
    category = "Cipher"

    def encode(self, text: str) -> str:
        rails = 7
        clean = [c.upper() for c in text if c.isalpha()]

        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for ch in clean:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        result = []
        for rail_list in fence:
            result.extend(rail_list)

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
