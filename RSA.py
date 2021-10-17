from PrimeGen import PrimeGen
from Common import Common

class RSA:

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

    def encrypt(n, e, m):
        return Common.powmod2(int.from_bytes(str.encode(str(m)), "big"), e, n)

    def decrypt(n, d, c):
        result = Common.powmod2(c, d, n)
        byteRestult = result.to_bytes((result.bit_length() + 7) // 8, "big")
        return byteRestult.decode()
