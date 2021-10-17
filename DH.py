import random

class DH:

    def genPrivateKey(p):
        return random.randint(1, p)

    def genPublicKey(p, g):
        return 0
        
