from methods.base import BaseMethod

class GermanPhoneticMethod(BaseMethod):
    name = "German Phonetic"
    description = "German language phonetic spelling"
    category = "Other"

    GERMAN = {
        'a':'ah','b':'beh','c':'tsay','d':'day','e':'eh',
        'f':'eff','g':'gay','h':'hah','i':'ee','j':'yot',
        'k':'kah','l':'ell','m':'emm','n':'enn','o':'oh',
        'p':'pay','q':'koo','r':'air','s':'ess','t':'tay',
        'u':'oo','v':'fow','w':'veh','x':'iks','y':'oo-psilon',
        'z':'tsett',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in self.GERMAN:
                result.append(self.GERMAN[lower])
            elif ch.isdigit():
                result.append(ch)
            elif ch.strip():
                result.append(ch)
        return ' '.join(result)
