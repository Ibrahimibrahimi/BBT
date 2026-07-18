from methods.base import BaseMethod


class ScytaleMethod(BaseMethod):
    name = "Scytale"
    description = "Scytale cipher: ancient Greek transposition device"
    category = "Cipher"

    def encode(self, text: str) -> str:
        diameter = 4
        clean = [c.upper() for c in text if c.isalpha()]

        row_count = (len(clean) + diameter - 1) // diameter
        grid = []
        idx = 0
        for r in range(row_count):
            row = []
            for c in range(diameter):
                if idx < len(clean):
                    row.append(clean[idx])
                    idx += 1
                else:
                    row.append(None)
            grid.append(row)

        result = []
        for c in range(diameter):
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
