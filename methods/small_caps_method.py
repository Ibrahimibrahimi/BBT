from methods.base import BaseMethod

class SmallCapsMethod(BaseMethod):
    name = "Small Caps"
    description = "Use Unicode small capital letters"
    category = "Other"

    MAP = {
        'a':'ᴀ','b':'ʙ','c':'ᴄ','d':'ᴅ','e':'ᴇ','f':'ꜰ','g':'ɢ','h':'ʜ',
        'i':'ɪ','j':'ᴊ','k':'ᴋ','l':'ʟ','m':'ᴍ','n':'ɴ','o':'ᴏ','p':'ᴘ',
        'q':'q','r':'ʀ','s':'ꜱ','t':'ᴛ','u':'ᴜ','v':'ᴠ','w':'ᴡ','x':'x',
        'y':'ʏ','z':'ᴢ'
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            lower = ch.lower()
            if lower in self.MAP:
                mapped = self.MAP[lower]
                result.append(mapped.upper() if ch.isupper() else mapped)
            else:
                result.append(ch)
        return ''.join(result)
