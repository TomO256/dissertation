import socket
import ssl
import threading

HOST = "127.0.0.1"
PORT = 5000

def listen(conn):
    while True:
        try:
            print(conn.recv(4096).decode(), end="")
        except:
            break

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2

# ✅ Disable CA verification (self‑signed)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = context.wrap_socket(sock, server_hostname="localhost")
conn.connect((HOST, PORT))

threading.Thread(target=listen, args=(conn,), daemon=True).start()

while True:
    msg = input()
    if msg == "/quit":
        break
    conn.sendall(msg.encode() + b"\n")

conn.close()