from methods.base import BaseMethod

class NatoExtendedMethod(BaseMethod):
    name = "NATO Extended"
    description = "NATO alphabet with phonetic pronunciation"
    category = "Other"

    NATO = {
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
            if upper in self.NATO:
                result.append(self.NATO[upper])
            elif ch.isdigit():
                result.append(ch)
            elif ch.strip():
                result.append(ch)
        return ' '.join(result)
