import socket
import ssl
import threading
import json
import hashlib
import binascii

HOST = "0.0.0.0"
PORT = 7580
USER_DB = "users.json"

clients = {}

def verify_user(username, password):
    try:
        with open(USER_DB) as f:
            db = json.load(f)
    except:
        return False

    if username not in db:
        return False

    salt = binascii.unhexlify(db[username]["salt"])
    stored_hash = db[username]["hash"]

    check = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 100_000
    )

    return binascii.hexlify(check).decode() == stored_hash


def handle_client(conn, addr):
    username = None
    try:
        conn.sendall(b"Username: ")
        username = conn.recv(1024).decode().strip()

        conn.sendall(b"Password: ")
        password = conn.recv(1024).decode().strip()

        if not verify_user(username, password):
            conn.sendall(b"AUTH FAILED\n")
            return

        conn.sendall(b"AUTH OK\n")
        clients[username] = conn
        print(f"[+] {username} logged in")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            msg = data.decode().strip()
            if not msg.startswith("@"):
                conn.sendall(b"ERROR: Use @user message\n")
                continue

            target, message = msg.split(" ", 1)
            target = target[1:]

            if target in clients:
                clients[target].sendall(
                    f"[{username}] {message}\n".encode()
                )
            else:
                conn.sendall(b"ERROR: User not online\n")

    finally:
        if username:
            clients.pop(username, None)
        conn.close()


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