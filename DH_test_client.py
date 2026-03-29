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
spk = serialize_public(s.recv(l))
l = (s.recv(8).decode())
# print("RAW:", repr(l))
# print("LEN:", len(l))
l = int(l)
ik = serialize_public(s.recv(l))
l = (s.recv(8).decode())
# print("RAW:", repr(l))
# print("LEN:", len(l))
l = int(l)
opk= serialize_public(s.recv(l))
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

## Client now has keys required and server can shut down

dh.x3dh(spk,ik,opk)
# print("SK "+dh.sk.hex())
dh.init_ratchets()
dh.dh_ratchet(spk)
# print("Intial ratchet: ", dh.send_ratchet.state)
pk = dh.DHratchet.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
s.send(bytesLength(pk))
s.sendall(pk)
dh.send(b"hello",s)
print(dh.recv(s))
dh.send(b"Goodbye",s)
print(dh.recv(s))
