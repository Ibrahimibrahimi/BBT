from methods.base import BaseMethod


class Murmur3Method(BaseMethod):
    name = "MurmurHash3"
    description = "MurmurHash3 32-bit (simplified)"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        nblocks = len(data) // 4
        h = 0
        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        for block_start in range(nblocks):
            k = int.from_bytes(data[block_start*4:(block_start+1)*4], 'little')
            k = (k * c1) & 0xFFFFFFFF
            k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
            k = (k * c2) & 0xFFFFFFFF
            h ^= k
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
            h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
        tail = data[nblocks*4:]
        k = 0
        for i, b in enumerate(tail):
            k |= b << (i * 8)
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h ^= len(data)
        h ^= (h >> 16)
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= (h >> 16)
        return f"{h:08x}"
