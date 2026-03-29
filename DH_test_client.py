import socket
from new_lib import *
import time
#### This is Alice

rsa= RSA()
s = socket.socket()
s.settimeout(20)
s.connect(("127.0.0.1",3456))
dh = DH_Sender()
l = (s.recv(8).decode())
# print("RAW:", repr(l))
# print("LEN:", len(l))
l = int(l)
spk = rsa.serialize_public(s.recv(l))
l = (s.recv(8).decode())
# print("RAW:", repr(l))
# print("LEN:", len(l))
l = int(l)
ik = rsa.serialize_public(s.recv(l))
l = (s.recv(8).decode())
# print("RAW:", repr(l))
# print("LEN:", len(l))
l = int(l)
opk= rsa.serialize_public(s.recv(l))
# print("RAW:", repr(l))
# print("LEN:", len(l))


things_to_send = [dh.IKa.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo),
                                        dh.EKa.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)]

for i in things_to_send:
    s.send(bytesLength(str(i)))
    s.sendall(i)
    time.sleep(0.2)
    
dh.x3dh(spk,ik,opk)
dh.init_ratchets()
pk = rsa.serialize_public(s.recv(int(s.recv(8).decode())))
dh.dh_ratchet(pk)

dh.send(b"hello",s)
print(dh.recv(s))
dh.send(b"Goodbye",s)
print(dh.recv(s))
