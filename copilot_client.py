import socket
import ssl
import threading

HOST = "127.0.0.1"   # Change to server IP
PORT = 5000

def receive_messages(conn):
    while True:
        try:
            msg = conn.recv(4096).decode()
            if not msg:
                break
            print(msg)
        except:
            break

def main():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED  # For testing; can enforce cert verification
    context.load_verify_locations("cert.pem")

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(raw_sock, server_hostname=HOST)

    conn.connect((HOST, PORT))
    print("[*] Connected to secure chat server.")

    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()

    while True:
        msg = input("")
        if msg.lower() == "/quit":
            break
        conn.send(msg.encode())

    conn.close()

if __name__ == "__main__":
    main()