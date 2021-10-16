import socket

def log(msg):
    print("CLIENT LOGGING: " + msg)

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to server
        log("Connecting to server")
        s.connect(("localhost", 50007))
        log("Connected")
        
        # Send setup request
        log("Sending setup request: Hello")
        s.sendall(b"hello")
        data = s.recv(2048)
        log("Key n received: data")
        data = s.recv(2048)
        log("Key e received: data")
