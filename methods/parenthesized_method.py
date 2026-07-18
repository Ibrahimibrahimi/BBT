from methods.base import BaseMethod

class ParenthesizedMethod(BaseMethod):
    name = "Parenthesized"
    description = "Wrap each character in parentheses with special Unicode"
    category = "Other"

    MAP = {
        'a':'⒜','b':'⒝','c':'⒞','d':'⒟','e':'⒠','f':'⒡','g':'⒢',
        'h':'⒣','i':'⒤','j':'⒥','k':'⒦','l':'⒧','m':'⒨','n':'⒩',
        'o':'⒪','p':'⒫','q':'⒬','r':'⒭','s':'⒮','t':'⒯','u':'⒰',
        'v':'⒱','w':'⒲','x':'⒳','y':'⒴','z':'⒵',
        'A':'⒜','B':'⒝','C':'⒞','D':'⒟','E':'⒠','F':'⒡','G':'⒢',
        'H':'⒣','I':'⒤','J':'⒥','K':'⒦','L':'⒧','M':'⒨','N':'⒩',
        'O':'⒪','P':'⒫','Q':'⒬','R':'⒭','S':'⒮','T':'⒯','U':'⒰',
        'V':'⒱','W':'⒲','X':'⒳','Y':'⒴','Z':'⒵',
        '0':'⑴','1':'⑵','2':'⑶','3':'⑷','4':'⑸','5':'⑹','6':'⑺',
        '7':'⑻','8':'Ⓖ','9':'Ⓗ','.':'．',',':'﹐','!':'！','?':'？',
    }

    def encode(self, text: str) -> str:
        return ''.join(self.MAP.get(c, c) for c in text)
