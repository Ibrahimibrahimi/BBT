from methods.base import BaseMethod


class CadenusMethod(BaseMethod):
    name = "Cadenus"
    description = "Cadenus cipher: keyword columnar transposition with alternating read directions"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "CADENUS"
        clean = [c.upper() for c in text if c.isalpha()]
        col_count = len(key)
        key_order = sorted(range(col_count), key=lambda i: (key[i], i))

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
                    row.append("")
            grid.append(row)

        result = []
        for rank, col in enumerate(key_order):
            if rank % 2 == 0:
                for r in range(row_count):
                    if grid[r][col]:
                        result.append(grid[r][col])
            else:
                for r in range(row_count - 1, -1, -1):
                    if grid[r][col]:
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
