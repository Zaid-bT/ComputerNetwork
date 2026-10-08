import socket 

s=socket.socket()
s.connect(("127.0.0.1",5000))

while True:
    msg = input("enter message: ")
    s.send(msg.encode())

    reply = s.recv(1024).decode()
    print("server reply: ",reply)

    if reply == "bye":
        break


s.close()
