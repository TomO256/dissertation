import socket
import ssl
import threading

HOST = "0.0.0.0"
PORT = 5000

clients = {}

def handle_client(conn, addr):
    try:
        conn.sendall(b"Username: ")
        username = conn.recv(1024).decode().strip()
        clients[username] = conn

        while True:
            data = conn.recv(4096)
            if not data:
                break

            msg = data.decode().strip()
            if not msg.startswith("@"):
                conn.send(b"ERROR: Use @user message\n")
                continue

            target, message = msg.split(" ", 1)
            target = target[1:]

            if target in clients:
                clients[target].sendall(
                    f"[{username}] {message}\n".encode()
                )
            else:
                conn.send(b"ERROR: User not online\n")

    finally:
        conn.close()
        clients.pop(username, None)

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("cert.pem", "key.pem")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    with context.wrap_socket(sock, server_side=True) as ssock:
        print("[SERVER] Listening securely")
        while True:
            conn, addr = ssock.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            ).start()

if __name__ == "__main__":
    main()