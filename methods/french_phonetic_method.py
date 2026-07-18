from methods.base import BaseMethod

class FrenchPhoneticMethod(BaseMethod):
    name = "French Phonetic"
    description = "French language phonetic spelling"
    category = "Other"

    FRENCH = {
        'a':'ah','b':'bay','c':'say','d':'day','e':'uh',
        'f':'eff','g':'zhay','h':'ahsh','i':'ee','j':'jee',
        'k':'kah','l':'ell','m':'emm','n':'enn','o':'oh',
        'p':'pay','q':'kay','r':'air','s':'ess','t':'tay',
        'u':'oo','v':'vay','w':'doo-bluh-vay','x':'eeks',
        'y':'ee-grec','z':'zed',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in self.FRENCH:
                result.append(self.FRENCH[lower])
            elif ch.isdigit():
                result.append(ch)
            elif ch.strip():
                result.append(ch)
        return ' '.join(result)
