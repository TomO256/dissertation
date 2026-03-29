from new_lib import *
import socket
import getpass

DEBUG = True

if DEBUG:
    IP = socket.gethostbyname(socket.gethostname())
    IP = "192.168.0.136"
else:
    IP = "81.109.22.44"

PORT = 2345

def login(x,y,z):
    print("working :)")
    return False

def connect():
    s = socket.socket()
    s.settimeout(20)
    try:
        s.connect((IP,PORT))
        rsa = RSA()
        encKey = rsa.exchangeKeys(s)
        ## Both client and server should now have three keys each
        rsa.send("HELLO",encKey,s)
        commCheck = rsa.recv(s)
        if commCheck == "HELLO":
            print("Established Secure Communication To Server")
            user = login(rsa,encKey,s)
            if user == False:
                print("Authenticated Failed - Disconnecting")
                return
            # mainloop(privKey,encKey,s,user)
            return
        elif commCheck == "FAIL":
            print("Failed to Establish Secure Communication on Client Side - Disconnecting")
            return
        else:
            print("Failed to Establish Secure Communication on Server Side - Disconnecting")
            return
    except ConnectionRefusedError:
        print("SERVER ERROR - Unable to find server at "+IP+":"+str(PORT)+"\nPlease check the server is running")

def login(rsa,encKey,sock):
    accountExists = input("Do you want to create a new account? (y/N)\n")
    if accountExists.upper()=="Y" or accountExists.upper()=="YES":
        createAccount(rsa,encKey,sock)
        return login(rsa,encKey,sock)
    username = input("Enter your username")
    pw = getpass.getpass("Enter your password")
    rsa.send("RETURNING USER",encKey,sock)
    rsa.send("USER:"+username+":USER PW:"+pw+":PW",encKey,sock)
    user = rsa.recv(sock)
    if user == "NULL":
        user=False
    return user

def createAccount(rsa,encKey,sock):
    un = input("Enter the username you wish to use\n")
    pw=getpass.getpass("Enter your chosen password\n")
    while pwcheck(pw) == False:
        print("Password must be at least 8 characters, include at least one uppercase, one lowercase and one number")
        pw = getpass.getpass("Enter your chosen password\n")
    pwconfirm = getpass.getpass("Please confirm your password\n")
    if pw!=pwconfirm:
        print("The passwords do not match, returning to Sign In")
        return
    rsa.send("NEW USER",encKey,sock)
    rsa.send("USER:"+un+":USER PW:"+pw+":PW",encKey,sock)
    response = rsa.recv(sock)
    if response == "SUCCESS":
        print("Account Created Succesfully, Generating Key Pair")
        sender=DH_Sender()
        reciever = DH_Reciever()
        #Order is:
        # 0: Sender IK, 1: Sender EK, 2: Recv SPK, 3: Recv IK, 4: Recv OPK
        content = [sender.IKa,sender.EKa,reciever.SPKb,reciever.IKb,reciever.OPKb]
        toWrite=[]
        for item in content:
            toWrite.append(getSendablePrivKey(item))
        with open(un+".key", "wb+") as f:
            for i in toWrite:
                f.write(i+b"\n")
        ## Send public keys to server
        
        for i in content:
            print("Sending "+str(i))
            rsa.send(getSendablePrivKey(i),encKey,sock)
        return
    else:
        print(response)
        print("Returning to Sign In")
        return


def pwcheck(password):
    return True
    if len(password) < 8:
        return False
    if password.upper() == password:
        return False
    if password.lower() == password:
        return False
    digit = any([i.isdigit() for i in password])
    if not digit:
        return False
    return True


connect()
