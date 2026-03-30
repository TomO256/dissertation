## PLAN

## User comms with Server using RSA + AES

## User comms with user using Signal Protocol DH Double Rachet

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
from Crypto.Cipher import AES # type: ignore

#################### A E S ############################
class AES_Enc(object):
    def __init__(self,key=Fernet.generate_key()):
        self.__key = key
        self.cipher = Fernet(key)
    def encrypt(self,msg):
        if type(msg) !=bytes:
            msg = msg.encode()
        return self.cipher.encrypt(msg)
    def decrypt(self,msg):
        return self.cipher.decrypt(msg)
    def getKey(self):
        return self.__key
    
    def setKey(self,key):
        self.__key = key
        self.cipher = Fernet(key)
        
    def send(self,msg,socket):
        # print("Attempting to send: "+msg+" using key: "+str(encKey))
        ct = self.encrypt(msg)
        socket.send(bytesLength(ct))
        socket.sendall(ct)

    def recv(self,socket,decode=True):
        length = int(socket.recv(8).decode())
        msg = socket.recv(length)
        msg = self.decrypt(msg)
        if decode:
            return msg.decode()
        return msg
    

#################### R S A ############################
class RSA(object):
    def __init__(self):
        self.__privKey = rsa.generate_private_key(public_exponent=65537,key_size=4096)
        self.__pubKey = self.__privKey.public_key()
        encryptedCheck = self.__pubKey.encrypt(b'Key Check',
                                        padding.OAEP(
                                            mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        ))
        encryptedCheck = self.__privKey.decrypt(encryptedCheck,
                                        padding.OAEP(
                                            mgf = padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        ))
        if encryptedCheck!=b"Key Check":
            print("Key Generation Failed")
            return RSA()
        
        self.pub_plain = self.__pubKey.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)

        self.priv_plain = self.__privKey.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption())

    def encrypt(self,msg,encryption_key):
        if type(msg) !=bytes:
            msg = msg.encode()
        return encryption_key.encrypt(
            msg,
            padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    
    def decrypt(self,ciphertext):
        return self.__privKey.decrypt(
            ciphertext,
            padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    
    def send(self,msg,encKey,socket):
        # print("Attempting to send: "+msg+" using key: "+str(encKey))
        ct = self.encrypt(msg,encKey)
        socket.send(bytesLength(ct))
        socket.sendall(ct)

    def recv(self,socket,decode=True):
        length = int(socket.recv(8).decode())
        msg = socket.recv(length)
        msg = self.decrypt(msg)
        if decode:
            return msg.decode()
        return msg
    
    def exchangeKeys(self,socket):
        ## On recieving a connection the sockets should create keys
        ## Send PublicKey
        socket.send(bytesLength(self.pub_plain))
        socket.sendall(self.pub_plain)
        ## Recv publickey
        leng = int(socket.recv(8).decode())
        encKey = socket.recv(leng)
        encKey = serialize_public(encKey)
        return encKey
        


############################### D H Signal Protocol ##################

def hkdf(string,length):
    hdkf = HKDF(algorithm=hashes.SHA256(),length=length,backend=default_backend())
    return hdkf.derive(string)

def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]

'I also skipped the verification of SPK_b’s signature as I couldn’t find a python library for it.'
' - Dont like this :/'
class SymmRatchet(object):
    def __init__(self,key):
        self.state = key

    def next(self,inp=b''):
        output = hkdf(self.state + inp,80)
        self.state = output[:32]
        outkey,iv = output[32:64], output[64:]
        return outkey, iv

class DH_Reciever(object):
    #Bob
    def __init__(self):
        ## Generate the required 3 private keys
        # IKb is the long term identity key
        self.IKb = X25519PrivateKey.generate()
        # SKb is the signed prekey (rotated periodically)
        self.SPKb = X25519PrivateKey.generate()
        #OPK is single time prekey, and deleted after use
        self.OPKb = X25519PrivateKey.generate()
        # Init initial DH ratchet
        self.DHratchet = self.SPKb

    def x3dh(self,IKa_pub_key,EKa_pub_key):
        ## Perform requried 4 DH key exchanges
        dh1 = self.SPKb.exchange(IKa_pub_key)
        dh2 = self.IKb.exchange(EKa_pub_key)
        dh3 = self.SPKb.exchange(EKa_pub_key)
        dh4 = self.OPKb.exchange(EKa_pub_key)
        self.sk = hkdf(dh1+dh2+dh3+dh4,32)
    
    def init_ratchets(self):
        self.root_ratchet = SymmRatchet(self.sk)
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])


    def dh_ratchet(self,public_key):
        dh_recv = self.DHratchet.exchange(public_key)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmRatchet(shared_recv)
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(public_key)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)

    # def send(self,msg,socket):
        
    #     key, iv = self.send_ratchet.next()
    #     ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
    #     toSend = ct+b":"+self.DHratchet.public_key().public_bytes(encoding=serialization.Encoding.PEM,
    #                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #     socket.send(bytesLength(toSend))
    #     # print("message sent: "+str(toSend))
    #     socket.send(toSend)

    def decrypt(self,msg,ratchet):
        self.dh_ratchet(ratchet)
        key, iv = self.recv_ratchet.next()
        final = AES.new(key,AES.MODE_CBC, iv).decrypt(msg)
        return unpad(final)

class DH_Sender(object):
    #Alice
    def __init__(self):
        self.IKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()
        self.DHratchet = None

    def x3dh(self,SPKb_pub_key, IKb_pub_key, OPKb_pub_key):
        dh1 = self.IKa.exchange(SPKb_pub_key)
        dh2 = self.EKa.exchange(IKb_pub_key)
        dh3 = self.EKa.exchange(SPKb_pub_key)
        dh4 = self.EKa.exchange(OPKb_pub_key)
        self.sk = hkdf(dh1+dh2+dh3+dh4,32)

    def init_ratchets(self):
        self.root_ratchet = SymmRatchet(self.sk)
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self,public_key):
        if self.DHratchet is not None:
            dh_recv = self.DHratchet.exchange(public_key)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            self.recv_ratchet = SymmRatchet(shared_recv)
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(public_key)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)

    def encrypt(self,msg):
        key, iv = self.send_ratchet.next()
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        ratchet = self.DHratchet.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return ct,ratchet

    # def recv(self,socket):
    #     leng = socket.recv(8).decode()
    #     msg = socket.recv(int(leng))
    #     msg = msg.split(b":")
    #     # print("Key found: "+str(msg[1]))
    #     self.dh_ratchet(serialize_public(msg[1]))
    #     key, iv = self.recv_ratchet.next()
    #     final = AES.new(key,AES.MODE_CBC, iv).decrypt(msg[0])
    #     return unpad(final)
######################## MISC FUNCTIONS ########################

def bytesLength(string):
    l = str(len(string))
    while len(l)<8:
        l="0"+l
    return l.encode()

def enclosed(string,delim):
    try:
        final = string.split(delim)
        final = final[1]
        return final[1:-1]
    except:
        return "ERROR"
    
def serialize_public(key):
    return serialization.load_pem_public_key(key)

def serialize_private(key):
    return serialization.load_pem_private_key(key,password=None)

def serialize_private_raw(key):
    return X25519PrivateKey.from_private_bytes(key)

def getSendablePrivKey(key):
    return key.private_bytes(encoding=serialization.Encoding.Raw,
                             format=serialization.PrivateFormat.Raw,
                             encryption_algorithm=serialization.NoEncryption())
    
def getSendablePubKey(key):
    return key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    