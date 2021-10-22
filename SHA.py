import hashlib

class SHA:
    def hash(message):
        hashed = hashlib.sha256(str(message).encode()).hexdigest()
        return hashed

    def hashNoHex(message):
        hashed = hashlib.sha256(str(message).encode()).digest()
        return hashed
