from methods.base import BaseMethod

class UpsideDownMethod(BaseMethod):
    name = "Upside Down"
    description = "Map chars to upside-down Unicode equivalents"
    category = "Other"

    FLIP = {
        'a':'ɐ','b':'q','c':'ɔ','d':'p','e':'ǝ','f':'ɟ','g':'ƃ','h':'ɥ',
        'i':'ᴉ','j':'ɾ','k':'ʞ','l':'l','m':'ɯ','n':'u','o':'o','p':'d',
        'q':'b','r':'ɹ','s':'s','t':'ʇ','v':'ʌ','w':'ʍ','x':'x','y':'ʎ',
        'z':'z','A':'∀','B':'q','C':'Ɔ','D':'p','E':'Ǝ','F':'Ⅎ','G':'⅁',
        'H':'H','I':'I','J':'ſ','K':'ʞ','L':'˥','M':'W','N':'N','O':'O',
        'R':'ɹ','S':'S','T':'⊥','V':'Λ','W':'M','X':'X','Y':'⅄','Z':'Z',
        '1':'Ɩ','2':'ᄅ','3':'Ɛ','4':'ㄣ','5':'ϛ','6':'9','7':'Ɫ','8':'8','9':'6','0':'0',
        ',':',','.':'˙',':':':','!':'¡','?':'¿','(':'[',')':']','[':'(',']':')',
        '{':'}','}':'{','<':'>','>':'<','\"':',',',':':','_':'‾','-':'-',
    }

    def encode(self, text: str) -> str:
        return ''.join(self.FLIP.get(c, c) for c in reversed(text))
