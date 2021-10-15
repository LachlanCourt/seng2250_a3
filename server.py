import socket






if __name__ == "__main__":
    s = socket.socket()
    s.bind(("", 50007))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print("Connected")
