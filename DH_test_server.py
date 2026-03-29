import socket
from new_lib import *
import time
rsa = RSA()
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("0.0.0.0",3456))
s.listen()
conn, addr = s.accept()
while True:
    print("Connection at: "+str(addr))
    dh = DH_Reciever()

    things_to_send = [dh.SPKb.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo), dh.IKb.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo), dh.OPKb.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)]
    for i in things_to_send:
        print("Sending: "+str(bytesLength(str(i))))
        conn.sendall(bytesLength(str(i)))
        conn.sendall(i)
        time.sleep(0.2)
    ik = serialize_public(conn.recv(int(conn.recv(8).decode())))
    ek = serialize_public(conn.recv(int(conn.recv(8).decode())))

    ## All keys should now be exchanged and server can 'go offline'

    dh.x3dh(ik,ek)
    # print("SK "+dh.sk.hex())
    dh.init_ratchets()
    pk = serialize_public(conn.recv(int(conn.recv(8).decode())))
    print(dh.recv(conn))
    dh.send(b"hi",conn)
    print(dh.recv(conn))
    dh.send(b"Bye",conn)
    break