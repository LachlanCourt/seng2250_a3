import socket

def log(msg):
    print("SERVER LOGGING: " + msg)

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
            log("Setup request received. Generating and sending RSA public key")
        
