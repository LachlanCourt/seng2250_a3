import hashlib

class SHA:
    def hash(message):
        hashed = hashlib.sha256(str(message).encode()).hexdigest()
        print(hashed)
        #hashedStr = str(int(hashedHex, 16))
        return hashed
