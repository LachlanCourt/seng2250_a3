import hashlib

class SHA:
    def hash(message):
        hashed = hashlib.sha256(str(message).encode()).hexdigest()
        return hashed
