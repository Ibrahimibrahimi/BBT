from methods.base import BaseMethod


class ChineseCipherMethod(BaseMethod):
    name = "Chinese Cipher"
    description = "Chinese Cipher: write right-to-left, read top-to-bottom"
    category = "Cipher"

    def encode(self, text: str) -> str:
        cols = 5
        clean = [c.upper() for c in text if c.isalpha()]

        row_count = (len(clean) + cols - 1) // cols
        grid = []
        idx = 0
        for r in range(row_count):
            row = []
            for c in range(cols):
                if idx < len(clean):
                    row.append(clean[idx])
                    idx += 1
                else:
                    row.append(None)
            grid.append(row)

        for row in grid:
            row.reverse()

        result = []
        for c in range(cols):
            for r in range(row_count):
                if grid[r][c] is not None:
                    result.append(grid[r][c])

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
