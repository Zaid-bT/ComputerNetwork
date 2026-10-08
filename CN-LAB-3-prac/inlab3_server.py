import socket

s=socket.socket()
print("socket created")

s.bind(("127.0.0.1",5000))

s.listen(5)

c,addr = s.accept()
print("connection from",addr)

while True:
    msg = c.recv(1024).decode()
    if msg == "bye":
        break
    print("client message: ",msg)

    reply = input("enter reply: ")
    c.send(reply.encode())

c.close()
s.close()