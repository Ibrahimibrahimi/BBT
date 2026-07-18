from methods.base import BaseMethod

class PoliceAlphabetMethod(BaseMethod):
    name = "Police Alphabet"
    description = "Police/emergency services phonetic"
    category = "Other"

    POLICE = {
        'A':'Adam','B':'Boy','C':'Charles','D':'David','E':'Edward',
        'F':'Frank','G':'George','H':'Henry','I':'Ida','J':'John',
        'K':'King','L':'Lincoln','M':'Mary','N':'Nora','O':'Ocean',
        'P':'Paul','Q':'Queen','R':'Robert','S':'Sam','T':'Tom',
        'U':'Uncle','V':'Victor','W':'William','X':'X-ray','Y':'Young',
        'Z':'Zebra',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            upper = ch.upper()
            if upper in self.POLICE:
                result.append(self.POLICE[upper])
            elif ch.isdigit():
                result.append(ch)
            elif ch.strip():
                result.append(ch)
        return ' '.join(result)
