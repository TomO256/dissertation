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
    if encryptedCheck!=b"Key Check":
        print("Key Generation Failed")
        return createKeys()
    print("Key Generation Succesful")
    return privKey,pubKey

def serialize_public(key):
    return serialization.load_pem_public_key(key)

def serialize_private(key):
    return serialization.load_pem_private_key(key,password=None)

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
    # print("Attempting to send: "+msg+" using key: "+str(encKey))
    ct = encrypt(msg,encKey)
    socket.send(bytesLength(ct))
    socket.sendall(ct)

def recv_encrypted_msg(decKey,socket):
    length = int(socket.recv(8).decode())
    msg = socket.recv(length)
    msg = decrypt(msg,decKey)
    return msg.decode()


def getSendablePubKey(key):
    return key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)

def getSendablePrivKey(key):
    return key.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption())

def exchangeKeys(pubKey,socket):
    pubKeyString = getSendablePubKey(pubKey)

    ## On recieving a connection the sockets should create keys
    ## Send PublicKey
    socket.send(bytesLength(pubKeyString))
    socket.sendall(pubKeyString)
    ## Recv publickey
    leng = int(socket.recv(8).decode())
    encKey = socket.recv(leng)
    encKey = serialize_public(encKey)
    return encKey

def write_key_to_file(privKey,file):
    with open(file, "+wb") as f:
        f.write(getSendablePrivKey(privKey))
    return

def read_key_from_file(file):
    try:
        with open(file,"rb") as f:
            privKey = serialize_private(f.read())
        return privKey
    except Exception as e:
        return False
def enclosed(string,delim):
    try:
        final = string.split(delim)
        final = final[1]
        return final[1:-1]
    except:
        return "ERROR"
    
