import socket

def log(msg):
    print("SERVER LOGGING: " + msg)


def powmod2(b, e, n):
    if n == 1:
        return 0
    rs = 1
    while (e > 0):
        if (e & 1) == 1:
            rs = (rs * b) % n
        e = e >> 1
        b = (b * b) % n
    return rs

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
        
