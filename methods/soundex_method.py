from methods.base import BaseMethod

class SoundexMethod(BaseMethod):
    name = "Soundex"
    description = "American Soundex phonetic algorithm"
    category = "Other"

    def encode(self, text: str) -> str:
        if not text:
            return ""
        text = text.upper()
        soundex = text[0]
        mapping = {'B':'1','F':'1','P':'1','V':'1','C':'2','G':'2','J':'2','K':'2','Q':'2','S':'2','X':'2','Z':'2','D':'3','T':'3','L':'4','M':'5','N':'5','R':'6'}
        prev = mapping.get(text[0], '0')
        for ch in text[1:]:
            code = mapping.get(ch, '0')
            if code != '0' and code != prev:
                soundex += code
            prev = code if code != '0' else prev
            if len(soundex) == 4:
                break
        return soundex.ljust(4, '0')
