from methods.base import BaseMethod

class SuperscriptMethod(BaseMethod):
    name = "Superscript"
    description = "Use Unicode superscript digits and letters"
    category = "Other"

    MAP = {
        '0':'⁰','1':'¹','2':'²','3':'³','4':'⁴','5':'⁵','6':'⁶','7':'⁷',
        '8':'⁸','9':'⁹','+':'⁺','-':'⁻','=':'⁼','(':'⁽',')':'⁾',
        'a':'ᵃ','b':'ᵇ','c':'ᶜ','d':'ᵈ','e':'ᵉ','f':'ᶠ','g':'ᵍ',
        'h':'ʰ','i':'ⁱ','j':'ʲ','k':'ᵏ','l':'ˡ','m':'ᵐ','n':'ⁿ',
        'o':'ᵒ','p':'ᵖ','r':'ʳ','s':'ˢ','t':'ᵗ','u':'ᵘ','v':'ᵛ','w':'ʷ',
        'x':'ˣ','y':'ʸ','z':'ᶻ','n':'ⁿ',
    }

    def encode(self, text: str) -> str:
        return ''.join(self.MAP.get(c.lower(), c) for c in text)
