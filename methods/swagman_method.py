from methods.base import BaseMethod


class SwagmanMethod(BaseMethod):
    name = "Swagman"
    description = "Swagman cipher: transposition using a keyword"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "SWAGMAN"
        clean = [c.upper() for c in text if c.isalpha()]
        key_order = sorted(range(len(key)), key=lambda i: (key[i], i))
        col_count = len(key)

        row_count = (len(clean) + col_count - 1) // col_count
        grid = []
        idx = 0
        for r in range(row_count):
            row = []
            for c in range(col_count):
                if idx < len(clean):
                    row.append(clean[idx])
                    idx += 1
                else:
                    row.append(None)
            grid.append(row)

        result = []
        for col in key_order:
            for r in range(row_count):
                if grid[r][col] is not None:
                    result.append(grid[r][col])

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
