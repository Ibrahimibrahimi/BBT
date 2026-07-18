from methods.base import BaseMethod


class AmscoMethod(BaseMethod):
    name = "AMSCO"
    description = "AMSCO cipher: columnar transposition with alternating 1-2 char groups"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "AMSCO"
        clean = [c.upper() for c in text if c.isalpha()]
        key_order = sorted(range(len(key)), key=lambda i: (key[i], i))

        col_count = len(key)
        pattern = []
        i = 0
        while len(pattern) < len(clean):
            pattern.append(1 if len(pattern) % 2 == 0 else 2)

        row_count = 0
        grid = []
        idx = 0
        while idx < len(clean):
            row = [None] * col_count
            for col in key_order:
                if idx >= len(clean):
                    break
                width = pattern[idx] if idx < len(pattern) else 1
                for w in range(width):
                    if idx < len(clean):
                        row[col] = row[col] + [clean[idx]] if row[col] else [clean[idx]]
                        idx += 1
            grid.append(row)
            row_count += 1

        result = []
        for col in key_order:
            for row in grid:
                if row[col]:
                    result.extend(row[col])
        return "".join(result)
