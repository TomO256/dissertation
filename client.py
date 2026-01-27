# Cloud Storage Client (Secure By Design)
import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

IP = "192.168.0.112"
PORT = 2345

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
    

def connect():
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((IP,PORT))
        privKey,  pubKey = createKeys()
        pubKeyString = pubKey.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)

        ## On recieving a connection the sockets should create keys
        ## Send PublicKey
        s.sendall(pubKeyString)
        ## Recv publickey
        encKey = s.recv(4096)
        encKey = serialization.load_pem_public_key(encKey)

        ## Both client and server should now have three keys each
        send_encrypted_msg("HELLO",encKey,s)
        commCheck = recv_encrypted_msg(privKey,s)
        if commCheck == "HELLO":
            print("Established Secure Communication")
            #remove this return when you return#
            return
        elif commCheck == "FAIL":
            print("Failed to Establish Secure Communication on Client Side - Disconnecting")
            return
        else:
            print("Failed to Establish Secure Communication on Server Side - Disconnecting")
            return
    except ConnectionRefusedError:
        print("SERVER ERROR - Unable to find server at "+IP+":"+str(PORT)+"\nPlease check the server is running")
connect()
