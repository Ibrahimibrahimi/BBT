from methods.base import BaseMethod


class RedefenceMethod(BaseMethod):
    name = "Redefence"
    description = "Redefence cipher: variant of rail fence with keyword ordering"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "REDEFENCE"
        key_order = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
        rails = len(keyword)
        clean = [c.upper() for c in text if c.isalpha()]

        fence = [[] for _ in range(rails)]
        idx = 0
        for i in range(len(clean)):
            rail = i % rails
            fence[rail].append(clean[i])

        result = []
        for rail_idx in key_order:
            result.extend(fence[rail_idx])

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
