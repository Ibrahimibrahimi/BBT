from methods.base import BaseMethod

class SpanishPhoneticMethod(BaseMethod):
    name = "Spanish Phonetic"
    description = "Spanish language phonetic spelling"
    category = "Other"

    SPANISH = {
        'a':'ah','b':'beh','c':'seh','d':'deh','e':'eh',
        'f':'efeh','g':'geh','h':'ah-cheh','i':'ee','j':'ho-ta',
        'k':'kah','l':'eh-leh','m':'eh-meh','n':'eh-neh','o':'oh',
        'p':'peh','q':'koo','r':'eh-rreh','s':'eh-seh','t':'teh',
        'u':'oo','v':'oo-veh','w':'doo-bleh oo-veh','x':'eh-kees',
        'y':'ee-gree-eh-ga','z':'seh-ta',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in self.SPANISH:
                result.append(self.SPANISH[lower])
            elif ch.isdigit():
                result.append(ch)
            elif ch.strip():
                result.append(ch)
        return ' '.join(result)
