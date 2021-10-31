### SENG2250 Assignment 3
### Lachlan Court
### c3308061
### 31/10/2021

from RSA import RSA
from SHA import SHA

MAX_MESSAGE_SIZE = 256

def serialise(data):
    return str.encode(str(data))

def deserialise(data):
    return data.decode()

class Comms:
    def recvRSAMessage(conn, rsan, rsae, keys):
        data = deserialise(conn.recv(10000))
        messages = data.split("#")
        message = messages[0]
        signature = messages[1]
        messageParts = message.split(",")
        signatureParts = signature.split(",")

        decryptedMessage = ""
        for i in range(len(messageParts)):
            decryptedSegment = RSA.decrypt(keys[0][0], keys[1], int(messageParts[i]))
            relevantSignature = signatureParts[i]
            hashedSegment = SHA.hash(decryptedSegment)
            signatureVerification = RSA.decrypt(rsan, rsae, int(relevantSignature))
            if hashedSegment != signatureVerification:
                return
            decryptedMessage += decryptedSegment
        return decryptedMessage

    def sendRSAMessage(s, rsan, rsae, keys, message):
        messages = []
        message = str(message)
        while len(message) > MAX_MESSAGE_SIZE:
            messages.append(message[:MAX_MESSAGE_SIZE])
            message = message[MAX_MESSAGE_SIZE:]
        messages.append(message)
        message = ""
        signature = ""
        for i in messages:
            message += str(RSA.encrypt(rsan, rsae, i)) + ","
            signature += str(RSA.encrypt(keys[0][0], keys[1], SHA.hash(i))) + ","
        # Remove trailing commas
        message = message[:len(message) - 1]
        signature = signature[:len(signature) - 1]
        data = message + "#" + signature
        s.sendall(serialise(data))
        return data
        
