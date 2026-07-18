from methods.base import BaseMethod

class ArabicTransliterationMethod(BaseMethod):
    name = "Arabic Transliteration"
    description = "Arabic to Latin transliteration"
    category = "Other"

    ARABIC = {
        'ا':'a','ب':'b','ت':'t','ث':'th','ج':'j','ح':'h','خ':'kh',
        'د':'d','ذ':'dh','ر':'r','ز':'z','س':'s','ش':'sh','ص':'s',
        'ض':'d','ط':'t','ظ':'dh','ع':'`','غ':'gh','ف':'f','ق':'q',
        'ك':'k','ل':'l','م':'m','ن':'n','ه':'h','و':'w','ي':'y',
        'ء':'\'','آ':'aa','أ':'a','ؤ':'u','إ':'i','ئ':'i','ة':'a',
        'ى':'a',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch in self.ARABIC:
                result.append(self.ARABIC[ch])
            elif ch.isascii():
                result.append(ch)
        return ''.join(result)
