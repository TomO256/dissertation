from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
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
    msg = msg.encode()
    return encryptionKey.encrypt(
        msg,
        padding.OAEP(
        mgf = padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

def bytesLength(string):
    l = str(len(string))
    while len(l)<8:
        l="0"+l
    return l.encode()

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
    socket.send(bytesLength(ct))
    socket.sendall(ct)

def recv_encrypted_msg(decKey,socket):
    length = int(socket.recv(8).decode())
    msg = socket.recv(length)
    msg = decrypt(msg,decKey)
    return msg.decode()

def exchangeKeys(pubKey,socket):
    pubKeyString = pubKey.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    ## On recieving a connection the sockets should create keys
    ## Send PublicKey
    socket.send(bytesLength(pubKeyString))
    socket.sendall(pubKeyString)
    ## Recv publickey
    leng = int(socket.recv(8).decode())
    encKey = socket.recv(leng)
    encKey = serialization.load_pem_public_key(encKey)
    return encKey

def enclosed(string,delim):
    final = string.split(delim)
    final = final[1]
    return final[1:-1]