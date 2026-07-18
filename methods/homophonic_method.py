from methods.base import BaseMethod


class HomophonicMethod(BaseMethod):
    name = "Homophonic"
    description = "Homophonic substitution cipher: each letter maps to multiple codes"
    category = "Cipher"

    def encode(self, text: str) -> str:
        mapping = {
            'A': ['21', '37', '53'], 'B': ['14'], 'C': ['32', '48'],
            'D': ['11', '27'], 'E': ['02', '18', '34', '50'], 'F': ['25'],
            'G': ['41'], 'H': ['07', '23'], 'I': ['16', '33', '49'],
            'J': ['58'], 'K': ['39'], 'L': ['05', '22'],
            'M': ['44'], 'N': ['10', '26', '42'], 'O': ['03', '19', '35', '51'],
            'P': ['28'], 'Q': ['55'], 'R': ['08', '24', '40'],
            'S': ['01', '17', '33', '49'], 'T': ['04', '20', '36', '52'],
            'U': ['12', '29'], 'V': ['45'], 'W': ['06', '23'],
            'X': ['56'], 'Y': ['13', '30'], 'Z': ['47']
        }

        import random
        random.seed(42)
        result = []
        for ch in text.upper():
            if ch in mapping:
                codes = mapping[ch]
                result.append(random.choice(codes))
            else:
                result.append(ch)
        return " ".join(result)
