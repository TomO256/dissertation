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
    ik = rsa.serialize_public(conn.recv(int(conn.recv(8).decode())))
    ek = rsa.serialize_public(conn.recv(int(conn.recv(8).decode())))

    

    dh.x3dh(ik,ek)
    dh.init_ratchets()
    pk = dh.DHratchet.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    conn.send(bytesLength(pk))
    conn.sendall(pk)
    print(dh.recv(conn))
    break