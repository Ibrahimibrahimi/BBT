from methods.base import BaseMethod

class ScriptMethod(BaseMethod):
    name = "Script"
    description = "Use Unicode mathematical script characters"
    category = "Other"

    MAP = {
        'a':'𝒶','b':'𝒷','c':'𝒸','d':'𝒹','e':'𝑒','f':'𝒻','g':'𝑔',
        'h':'𝒽','i':'𝒾','j':'𝒿','k':'𝓀','l':'𝓁','m':'𝓂','n':'𝓃',
        'o':'𝑜','p':'𝓅','q':'𝓆','r':'𝓇','s':'𝓈','t':'𝓉','u':'𝓊',
        'v':'𝓋','w':'𝓌','x':'𝓍','y':'𝓎','z':'𝓏',
        'A':'𝒜','B':'𝒞','C':'𝒟','D':'𝐹','E':'𝐺','F':'𝐻','G':'𝐼',
        'H':'𝒥','I':'𝒦','J':'𝐿','K':'𝑀','L':'𝒩','M':'𝒪','N':'𝒫',
        'O':'𝒬','P':'𝑅','Q':'𝒮','R':'𝒯','S':'𝒰','T':'𝒱','U':'𝒲',
        'V':'𝒳','W':'𝒴','X':'𝒵',
    }

    def encode(self, text: str) -> str:
        return ''.join(self.MAP.get(c, c) for c in text)
