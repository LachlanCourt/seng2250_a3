### SENG2250 Assignment 3
### Lachlan Court
### c3308061
### 31/10/2021

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from SHA import SHA
 
BLOCK_SIZE = 16

class AES2:
    def encrypt(message, key):
        messages = []
        while len(message) > 16:
            messages.append(message[:BLOCK_SIZE])
            message = message[BLOCK_SIZE:]
        messages.append(message)
        
        initialIv = str.encode(b64encode(get_random_bytes(BLOCK_SIZE)).decode()[:16])
        iv = initialIv
        encrypted = ""
        for i in messages:
            cipher = AES.new(key=SHA.hashNoHex(str(key)), mode=AES.MODE_ECB)
            aesblock = cipher.encrypt(iv)
            ciphertext = int.from_bytes(aesblock, "big") ^ int.from_bytes(str.encode(str(i)), "big")
            encrypted += b64encode(ciphertext.to_bytes((ciphertext.bit_length() + 7) // 8, "big")).decode()
            iv = AES2.incIV(iv)
            
        return initialIv.decode() + "," + encrypted
     
     
    def decrypt(data, key):
        iv = str.encode(data.split(",")[0])
        encrypted = data.split(",")[1]
        encryptions = []
        while len(encrypted) > 24:
            encryptions.append(encrypted[:24])
            encrypted = encrypted[24:]
        encryptions.append(encrypted)

        message = ""
        for i in encryptions:
            cipher = AES.new(key=SHA.hashNoHex(str(key)), mode=AES.MODE_ECB)
            aesblock = cipher.encrypt(iv)
            decoded = b64decode(i)
            s = int.from_bytes(aesblock, "big") ^ int.from_bytes(decoded, "big")
            message += s.to_bytes((s.bit_length() + 7) // 8, "big").decode()
            iv = AES2.incIV(iv)
        
        return message

    def incIV(iv):
        iv = int.from_bytes(iv, "big") + 1
        iv = iv.to_bytes((iv.bit_length() + 7) // 8, "big")
        return iv



##class AES2:
##    def encrypt(message, key):
##        cipher = AES.new(key=SHA.hashNoHex(str(key)), mode=AES.MODE_CTR)
##        encrypted = b64encode(cipher.encrypt(str.encode(str(message)))).decode()
##        iv = b64encode(cipher.nonce).decode()        
##
##        return iv + "," + encrypted
##     
##     
##    def decrypt(data, key):
##        iv = b64decode(data.split(",")[0])
##        encrypted = b64decode(data.split(",")[1])
##        cipher = AES.new(key=SHA.hashNoHex(str(key)), mode=AES.MODE_CTR, nonce=iv)
##        return cipher.decrypt(encrypted).decode()
