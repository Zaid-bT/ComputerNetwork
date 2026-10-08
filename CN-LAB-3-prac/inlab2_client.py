import socket

s= socket.socket()
print("socket created")

s.connect(("127.0.0.1",5000))

while True:
    name = input("Enter name: ")

    s.send(name.encode())
    if name == "zero":
        break

    msg = s.recv(1024).decode()

    print("server message: ",msg)

s.close()