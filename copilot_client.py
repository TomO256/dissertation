import socket
import ssl
import threading

HOST = "81.109.22.44"
PORT = 7580

def listen(conn):
    while True:
        try:
            print(conn.recv(4096).decode(), end="")
        except:
            break

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(sock, server_hostname="localhost")
conn.connect((HOST, PORT))

print(conn.recv(1024).decode(), end="")
conn.sendall(input().encode() + b"\n")

print(conn.recv(1024).decode(), end="")
conn.sendall(input().encode() + b"\n")

response = conn.recv(1024).decode()
print(response)
if "FAILED" in response:
    conn.close()
    exit()

threading.Thread(target=listen, args=(conn,), daemon=True).start()

while True:
    msg = input()
    if msg == "/quit":
        break
    conn.sendall(msg.encode() + b"\n")

conn.close()