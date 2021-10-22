from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from SHA import SHA
 
BLOCK_SIZE = 16

class AES2:
    def encrypt(message, key):
        cipher = AES.new(key=SHA.hashNoHex(str(key)), mode=AES.MODE_CTR)
        encrypted = b64encode(cipher.encrypt(str.encode(str(message)))).decode()
        iv = b64encode(cipher.nonce).decode()        

        return iv + "," + encrypted
     
     
    def decrypt(data, key):
        iv = b64decode(data.split(",")[0])
        encrypted = b64decode(data.split(",")[1])
        cipher = AES.new(key=SHA.hashNoHex(str(key)), mode=AES.MODE_CTR, nonce=iv)
        return cipher.decrypt(encrypted).decode()

