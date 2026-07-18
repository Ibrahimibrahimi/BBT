from methods.base import BaseMethod


class ColumnarTranspositionMethod(BaseMethod):
    name = "Columnar Transposition"
    description = 'Keyword-based column reorder cipher, key="SECRET"'
    category = "Cipher"

    KEY = "SECRET"

    def encode(self, text: str) -> str:
        key = self.KEY
        num_cols = len(key)
        sorted_key = sorted(range(num_cols), key=lambda i: (key[i], i))

        num_rows = -(-len(text) // num_cols)
        grid = []
        idx = 0
        for r in range(num_rows):
            row = []
            for c in range(num_cols):
                if idx < len(text):
                    row.append(text[idx])
                    idx += 1
                else:
                    row.append('')
            grid.append(row)

        result = []
        for col_idx in sorted_key:
            for r in range(num_rows):
                if grid[r][col_idx]:
                    result.append(grid[r][col_idx])
        return "".join(result)
