from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import socket

def createKeys():
    privKey = rsa.generate_private_key(public_exponent=65537,key_size=4096)
    pubKey = privKey.public_key()
    encryptedCheck = pubKey.encrypt(b'Key Check',
                                    padding.OAEP(
                                        mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    ))
    encryptedCheck = privKey.decrypt(encryptedCheck,
                                     padding.OAEP(
                                        mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    ))
    print(encryptedCheck)
    if encryptedCheck!=b"Key Check":
        print("Key Generation Failed")
        return createKeys()
    print("Key Generation Succesful")
    return privKey,pubKey

def encrypt(msg,encryptionKey):
    msg = msg.encode().strip()
    return encryptionKey.encrypt(
        msg,
        padding.OAEP(
        mgf = padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def decrypt(msg,decryptionKey):
    return decryptionKey.decrypt(
        msg,
        padding.OAEP(
        mgf = padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def send_encrypted_msg(msg,encKey,socket):
    ct = encrypt(msg,encKey)
    socket.sendall(ct)

def recv_encrypted_msg(decKey,socket):
    msg = socket.recv(4096)
    msg = decrypt(msg,decKey)
    return msg.decode()

IP = "192.168.0.112"
PORT = 2345
def startup():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((IP,PORT))
    s.listen()
    conn, addr = s.accept()
    while True:
        print("Connection at: "+str(addr))
        encKey = conn.recv(5000)
        print(encKey)
        encKey = serialization.load_pem_public_key(encKey)
        privKey, pubKey = createKeys()
        pubKeyString = pubKey.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
        conn.send(pubKeyString)

        ## Both client and server should now have three keys
        msgToSend = "HELLO"
        check = recv_encrypted_msg(privKey,conn)
        if check!="HELLO":
            msgToSend="FAIL"
        send_encrypted_msg(msgToSend,encKey,conn)
        return

    
startup()