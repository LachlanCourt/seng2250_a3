import socket
from RSA import RSA
from IdGen import IdGen
from SHA import SHA

def log(msg):
    print("SERVER LOGGING: " + msg)

def serialise(data):
    return str.encode(str(data))

def deserialise(data):
    return data.decode()
    
def recvEncryptedMessage(conn, rsan, rsae, keys):
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

PORT = 50007

if __name__ == "__main__":
    s = socket.socket()
    idGen = IdGen()
    s.bind(("", PORT))
    s.listen(1)
    log("Listening on port " + str(PORT))
    conn, addr = s.accept()
    with conn:
        log("Client has connected")
        while True:
            # Receive setup request
            data = conn.recv(1024)
            if not data:
                break
            if data == b'Hello': # Setup request
                # Generate and send keys
                log("Setup request received. Generating server RSA keys")
                keys = RSA.genRSA()
                log(f"Sending RSA public key n: \n{keys[0][0]}")
                conn.sendall(serialise(keys[0][0])) # public key n
                log(f"Sending RSA public key e: \n{keys[0][1]}")
                conn.sendall(serialise(keys[0][1])) # public key e

                # Receive keys
                data = conn.recv(2048)
                rsan = int(deserialise(data))
                log(f"Key n received: \n{rsan}")
                data = conn.recv(2048)
                rsae = int(deserialise(data))
                log(f"Key e received: \n{rsae}")
                
            elif len(data) == 20: # Client Hello
                idc = data
                log(f"Client hello received: \n{idc}")
                # Generate and send server ID and session ID
                ids = idGen.getID(20)
                sid = idGen.getID(30)
                log(f"Sending IDs: \n{ids}")
                conn.sendall(serialise(ids)) # IDs
                log(f"Sending SID: \n{sid}")
                conn.sendall(serialise(sid)) # SID

                ## Receive p for DH key exchange
                DHp = int(recvEncryptedMessage(conn, rsan, rsae, keys))
                log(f"Received DH prime p: \n{DHp}")
                # Receive g for DH key exchange
                DHg = int(recvEncryptedMessage(conn, rsan, rsae, keys))
                log(f"Received DH generator g: \n{DHg}")

                dhPriv = DH.getPrivateKey(DHp)
                log(f"Generatred DH private key: \n{dhPriv}")

                
            else: # Invalid
                log("Invalid request. Terminating connection")
                conn.close()
                break























            
