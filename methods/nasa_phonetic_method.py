from methods.base import BaseMethod

class NasaPhoneticMethod(BaseMethod):
    name = "NASA Phonetic"
    description = "NASA/aviation phonetic alphabet"
    category = "Other"

    NASA = {
        'A':'Alpha','B':'Bravo','C':'Charlie','D':'Delta','E':'Echo',
        'F':'Foxtrot','G':'Golf','H':'Hotel','I':'India','J':'Juliett',
        'K':'Kilo','L':'Lima','M':'Mike','N':'November','O':'Oscar',
        'P':'Papa','Q':'Quebec','R':'Romeo','S':'Sierra','T':'Tango',
        'U':'Uniform','V':'Victor','W':'Whiskey','X':'X-ray','Y':'Yankee',
        'Z':'Zulu',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            upper = ch.upper()
            if upper in self.NASA:
                result.append(self.NASA[upper])
            elif ch.isdigit():
                result.append(ch)
            elif ch.strip():
                result.append(ch)
        return ' '.join(result)
