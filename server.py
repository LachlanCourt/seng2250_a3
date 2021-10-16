import socket
from RSA import RSA
from IdGen import IdGen

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
                log("Setup request received. Generating RSA keys")
                keys = RSA.genRSA()
                log(f"Sending RSA public key n: \n{keys[0][0]}")
                conn.sendall(serialise(keys[0][0])) # public key n
                log(f"Sending RSA public key e: \n{keys[0][1]}")
                conn.sendall(serialise(keys[0][1])) # public key e
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

                data = conn.recv(2028)
                log(f"Data received: \n{deserialise(data)}")
                decoded = RSA.decrypt(keys[0][0], keys[1], int(deserialise(data)))
                log(f"Decrypted message: \n{decoded}")
                
            else: # Invalid
                log("Invalid request. Terminating connection")
                conn.close()
                break
