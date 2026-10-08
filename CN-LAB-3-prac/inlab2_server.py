import socket

s= socket.socket()
print("socket created")

s.bind(("127.0.0.1",5000))
s.listen(5)
c, addr = s.accept()
print("connection from", addr)

while True:    
    name = c.recv(1024).decode()
    if name == "zero":
        break

    msg = "welcome " + name + " to the server"

    c.send(msg.encode())

c.close()
s.close()
    