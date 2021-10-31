### SENG2250 Assignment 3
### Lachlan Court
### c3308061
### 31/10/2021

import hashlib

class SHA:
    def hash(message):
        hashed = hashlib.sha256(str(message).encode()).hexdigest()
        return hashed

    def hashNoHex(message):
        hashed = hashlib.sha256(str(message).encode()).digest()
        return hashed
