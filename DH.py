import random
from Common import Common

class DH:

    def genPrivateKey(p):
        return random.randint(1, p)

    def genPublicKey(p, g, priv):
        return Common.powmod2(g, priv, p)

    def genSessionKey(pub, priv, p):
        return Common.powmod2(pub, priv, p)
        
