from methods.base import BaseMethod


class JenkinsOATMethod(BaseMethod):
    name = "Jenkins OAT"
    description = "Jenkins One-at-a-Time hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        for b in text.encode():
            h = (h + b) & 0xFFFFFFFF
            h = (h + (h << 10)) & 0xFFFFFFFF
            h ^= (h >> 6) & 0xFFFFFFFF
        h = (h + (h << 3)) & 0xFFFFFFFF
        h ^= (h >> 11) & 0xFFFFFFFF
        h = (h + (h << 15)) & 0xFFFFFFFF
        return f"{h:08x}"
