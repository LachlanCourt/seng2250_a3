from PrimeGen import PrimeGen

class RSA:
    def powmod2(b, e, n):
        if n == 1:
            return 0
        rs = 1
        while (e > 0):
            if (e & 1) == 1:
                rs = (rs * b) % n
            e = e >> 1
            b = (b * b) % n
        return rs

    def genRSA():
        e = 65537 # as per spec
        p = PrimeGen.getPrime()
        q = p
        while p == q:
            q = PrimeGen.getPrime()
        n = p * q
        phi = (p - 1) * (q - 1)
        #d = (1 % phi) / e
        d = pow(e, -1, phi)
        
        return [(n, e), d]
