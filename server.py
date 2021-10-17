import socket
from RSA import RSA
from IdGen import IdGen
from SHA import SHA
from Comms import Comms
from DH import DH

def log(msg):
    print("SERVER LOGGING: " + msg)

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
                DHp = int(Comms.recvEncryptedMessage(conn, rsan, rsae, keys))
                log(f"Received DH prime p: \n{DHp}")
                # Receive g for DH key exchange
                DHg = int(Comms.recvEncryptedMessage(conn, rsan, rsae, keys))
                log(f"Received DH generator g: \n{DHg}")

                # Generate DH keys
                dhPriv = DH.genPrivateKey(DHp)
                log(f"Generated DH private key: \n{dhPriv}")
                dhPub = DH.genPublicKey(DHp, DHg, dhPriv)
                # Send public key
                encrypted = Comms.sendEncryptedMessage(conn, rsan, rsae, keys, dhPub)
                log(f"Sending RSA encrypted public key: \n{encrypted}")

                # Receive client public key
                clientPub = int(Comms.recvEncryptedMessage(conn, rsan, rsae, keys))
                log(f"Received DH public key: \n{clientPub}")

                # Calculate session key
                sessionKey = DH.genSessionKey(clientPub, dhPriv, DHp)
                log(f"Calculated session key: \n{sessionKey}")
                
            else: # Invalid
                log("Invalid request. Terminating connection")
                conn.close()
                break























            
