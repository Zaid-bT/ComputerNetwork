import socket

hostname = socket.gethostname()
host_ip = socket.gethostbyname(hostname)

print("Hostname:", hostname)
print("IP Address:", host_ip)