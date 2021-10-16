import socket
from IdGen import IdGen

def log(msg):
    print("CLIENT LOGGING: " + msg)

def serialise(d):
    return str.encode(str(d))

if __name__ == "__main__":
    idGen = IdGen()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to server
        log("Connecting to server")
        s.connect(("localhost", 50007))
        log("Connected")
        
        # Send setup request
        log("Sending setup request: Hello")
        s.sendall(b"Hello")

        # Receive keys
        data = s.recv(2048)
        rsan = data
        log(f"Key n received: \n{rsan}")
        data = s.recv(2048)
        rsae = data
        log(f"Key e received: \n{rsae}")

        # Send Client Hello
        idc = idGen.getID(20)
        log(f"Sending client hello:\n {idc}")
        s.sendall(serialise(idc))

        # Receive IDs and SID
        data = s.recv(2048)
        ids = data
        log(f"IDs received: \n{ids}")
        data = s.recv(2048)
        sid = data
        log(f"SID received: \n{sid}")
        
