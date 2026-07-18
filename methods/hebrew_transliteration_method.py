from methods.base import BaseMethod

class HebrewTransliterationMethod(BaseMethod):
    name = "Hebrew Transliteration"
    description = "Hebrew to Latin transliteration"
    category = "Other"

    HEBREW = {
        'א':'','ב':'b','ג':'g','ד':'d','ה':'h','ו':'v','ז':'z',
        'ח':'ch','ט':'t','י':'y','ך':'ch','כ':'ch','ל':'l','ם':'m',
        'מ':'m','ן':'n','נ':'n','ס':'s','ע':'`','ף':'f','פ':'p',
        'ץ':'ts','צ':'ts','ק':'q','ר':'r','ש':'sh','ת':'t',
        'װ':'v','ױ':'oy','ײ':'ey',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch in self.HEBREW:
                translit = self.HEBREW[ch]
                result.append(translit if translit else '')
            elif ch.isascii():
                result.append(ch)
        return ''.join(result)
