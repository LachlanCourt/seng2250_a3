import socket
from RSA import RSA

def log(msg):
    print("SERVER LOGGING: " + msg)

def serialise(d):
    return str.encode(str(d))
    

PORT = 50007

if __name__ == "__main__":
    s = socket.socket()
    s.bind(("", PORT))
    s.listen(1)
    log("Listening on port " + str(PORT))
    conn, addr = s.accept()
    with conn:
        log("Client has connected")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            if data != b'hello':
                log("Invalid setup request. Terminating connection")
                conn.close()
                break
            log("Setup request received. Generating RSA keys")
            keys = RSA.genRSA()
            conn.sendall(serialise(keys[0][0])) # public key n
            conn.sendall(serialise(keys[0][1])) # public key e
            print(keys)
