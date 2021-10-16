import random

class IdGen:

    def __init__(self):
        candidates = []
        for i in range(48, 58):
            candidates.append(i)
        for i in range(65, 91):
            candidates.append(i)        
        self.candidates = candidates
    
    def getID(self, length):
        iden = ""
        for i in range(length):
            iden += chr(random.choice(self.candidates))
        return iden
            
