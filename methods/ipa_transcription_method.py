from methods.base import BaseMethod

class IPATranscriptionMethod(BaseMethod):
    name = "IPA Transcription"
    description = "International Phonetic Alphabet approximation"
    category = "Other"

    IPA = {
        'a':'/a/','b':'/b/','c':'/k/','d':'/d/','e':'/ɛ/','f':'/f/',
        'g':'/ɡ/','h':'/h/','i':'/i/','j':'/dʒ/','k':'/k/','l':'/l/',
        'm':'/m/','n':'/n/','o':'/o/','p':'/p/','q':'/k/','r':'/ɹ/',
        's':'/s/','t':'/t/','u':'/u/','v':'/v/','w':'/w/','x':'/ks/',
        'y':'/j/','z':'/z/',
        'A':'/eɪ/','B':'/biː/','C':'/siː/','D':'/diː/','E':'/iː/',
        'F':'/ɛf/','G':'/dʒiː/','H':'/eɪtʃ/','I':'/aɪ/','J':'/dʒeɪ/',
        'K':'/keɪ/','L':'/ɛl/','M':'/ɛm/','N':'/ɛn/','O':'/oʊ/',
        'P':'/piː/','Q':'/kjuː/','R':'/ɑːr/','S':'/ɛs/','T':'/tiː/',
        'U':'/juː/','V':'/viː/','W':'/dʌbljuː/','X':'/ɛks/',
        'Y':'/waɪ/','Z':'/ziː/',
    }

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch in self.IPA:
                result.append(self.IPA[ch])
            elif ch.isdigit():
                result.append(f'/{ch}/')
            elif ch.strip():
                result.append(f'/{ch}/')
        return ' '.join(result)
