import socket
from RSA import RSA
from IdGen import IdGen
from SHA import SHA
from Comms import Comms
from DH import DH
from Hmac import Hmac
from AES2 import AES2

def log(msg):
    print("\nSERVER LOGGING: " + msg)

def serialise(data):
    return str.encode(str(data))

def deserialise(data):
    return data.decode()
    


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
                sendMessage = str(keys[0][0]) + "#" + str(keys[0][1])
                log(f"Sending RSA public keys: \n{sendMessage}")
                conn.sendall(serialise(sendMessage)) # public key n and e

                # Receive keys
                data = deserialise(conn.recv(2048)).split("#")
                rsan = int(data[0])
                log(f"Key n received: \n{rsan}")
                rsae = int(data[1])
                log(f"Key e received: \n{rsae}")
                
            elif len(data) == 20: # Client Hello
                idc = deserialise(data)
                log(f"Client hello received: \n{idc}")
                # Generate and send server ID and session ID
                ids = idGen.getID(20)
                sid = idGen.getID(30)
                log(f"Sending IDs: \n{ids}")
                conn.sendall(serialise(ids)) # IDs
                log(f"Sending SID: \n{sid}")
                conn.sendall(serialise(sid)) # SID

                ## Receive p for DH key exchange
                DHp = int(Comms.recvRSAMessage(conn, rsan, rsae, keys))
                log(f"Received DH prime p: \n{DHp}")
                # Receive g for DH key exchange
                DHg = int(Comms.recvRSAMessage(conn, rsan, rsae, keys))
                log(f"Received DH generator g: \n{DHg}")

                # Generate DH keys
                dhPriv = DH.genPrivateKey(DHp)
                log(f"Generated DH private key: \n{dhPriv}")
                dhPub = DH.genPublicKey(DHp, DHg, dhPriv)
                # Send public key encrypted with RSA to prevent against MITM attacks
                encrypted = Comms.sendRSAMessage(conn, rsan, rsae, keys, dhPub)
                log(f"Sending RSA encrypted public key: \n{encrypted}")

                # Receive client public key
                clientPub = int(deserialise(conn.recv(10000)))
                log(f"Received DH public key: \n{clientPub}")

                # Calculate session key
                sessionKey = DH.genSessionKey(clientPub, dhPriv, DHp)
                log(f"Calculated session key: \n{sessionKey}")

                # Check session key
                clientHashed = deserialise(conn.recv(10000))
                log(f"Received client hashed key with id and session id:\n{clientHashed}")
                testHashed = SHA.hash(str(sessionKey) + idc + sid)
                if clientHashed != testHashed:
                    conn.close()
                    continue
                log("Client session key is valid")

                serverHashed = SHA.hash(str(sessionKey) + idc + ids + sid)
                log(f"Sending hashed key with both ids and session id: \n{serverHashed}")
                conn.sendall(serialise(serverHashed))

                ###### Data Exchange ######
                
                # Receive message from client
                data = deserialise(conn.recv(10000)).split("#")
                log(f"Received AES encrypted message with hash verification: \n{data}")
                if not Hmac.verHmac(data[0], data[1], sessionKey):
                    conn.close()
                    continue
                log(f"Hash verified data: \n{data[0]}")
                message = AES2.decrypt(data[0], sessionKey)
                log(f"Decrypted AES data to original message: \n{message}")

                # Send message
                message = "Thankyou for the message I really appreciated the perfect length"
                log(f"Message to be sent to client:\n{message}")
                encryptedMessage = AES2.encrypt(message, sessionKey)
                #encryptedMessage = message
                log(f"Generated encrypted message: \n{encryptedMessage}")
                # Create HMAC from session key
                messageMac = Hmac.hmac(encryptedMessage, sessionKey)
                log(f"Hashed message for integrity: \n{messageMac}")
                sendMessage = encryptedMessage + "#" + messageMac
                conn.sendall(serialise(sendMessage))
                log(f"Sending encrypted message: \n{message}")

                
            else: # Invalid
                log("Invalid request. Terminating connection")
                conn.close()
                break























            
