import socket
import ssl
import threading

HOST = "0.0.0.0"
PORT = 5000

clients = []

def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    try:
        while True:
            msg = conn.recv(4096)
            if not msg:
                break

            broadcast(msg, conn)
    finally:
        conn.close()
        clients.remove(conn)
        print(f"[-] Disconnected: {addr}")

def broadcast(message, sender):
    for c in clients:
        if c != sender:
            c.send(message)

def main():
    print("[*] Starting secure chat server...")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[*] Listening on {HOST}:{PORT}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                clients.append(conn)
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.start()

if __name__ == "__main__":
    main()