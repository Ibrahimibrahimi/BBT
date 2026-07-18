from methods.base import BaseMethod

class GreekPhoneticMethod(BaseMethod):
    name = "Greek Phonetic"
    description = "Greek alphabet transliteration"
    category = "Other"

    GREEK = {
        'a':'alpha','b':'beta','g':'gamma','d':'delta','e':'epsilon',
        'z':'zeta','h':'eta','i':'iota','k':'kappa','l':'lambda',
        'm':'mu','n':'nu','x':'xi','o':'omicron','p':'pi',
        'r':'rho','s':'sigma','t':'tau','u':'upsilon','f':'phi',
        'c':'chi','y':'psi','w':'omega',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in self.GREEK:
                word = self.GREEK[lower]
                result.append(word.capitalize() if ch.isupper() else word)
            else:
                result.append(ch)
        return ''.join(result)
