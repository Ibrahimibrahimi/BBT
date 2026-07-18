from methods.base import BaseMethod


class RouteTranspositionMethod(BaseMethod):
    name = "Route Transposition"
    description = "Route Transposition: write in grid, read in spiral pattern"
    category = "Cipher"

    def encode(self, text: str) -> str:
        cols = 6
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

        result = []
        top, bottom = 0, row_count - 1
        left, right = 0, cols - 1

        while top <= bottom and left <= right:
            for r in range(top, bottom + 1):
                if grid[r][left] is not None:
                    result.append(grid[r][left])
            left += 1
            for c in range(left, right + 1):
                if grid[bottom][c] is not None:
                    result.append(grid[bottom][c])
            bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if grid[r][right] is not None:
                        result.append(grid[r][right])
                right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if grid[top][c] is not None:
                        result.append(grid[top][c])
                top += 1

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
