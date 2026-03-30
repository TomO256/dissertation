from final_lib import *
import socket
import getpass

DEBUG = True

if DEBUG:
    IP = socket.gethostbyname(socket.gethostname())
    IP = "192.168.0.136"
    PORT = 2345
else:
    IP = "81.109.22.44"
    PORT = 7579



def menu():
    print("----- M E N U ------")
    print("1.\tSend Message")
    print("2.\tView Messages")
    print("0.\tQuit")
    choice = -1
    try:
        choice = int(input())
    except:
        pass
    while choice not in [0,1,2]:
        print("Please enter a valid option")
        try:
            choice = int(input())
        except:
            pass
    return choice
        
        
def mainloop(aes,sock,user):
    while 1:
        choice = menu()
        if choice==1:
            sendMessage(aes,sock,user)
        elif choice==2:
            viewMessages(aes,sock,user)
        else:
            print("Closing Secure Connection")
            sock.close()
            return

def viewMessages(aes,sock,user):
    aes.send("VIEWMESSAGE",sock)
    numMessages = aes.recv(sock)
    print("You have received: "+str(numMessages)+" messages")
    dh = DH_Reciever()
    privKeys = getPrivKeys(user)
    dh.SPKb = privKeys[2]
    dh.IKb = privKeys[3]
    dh.OPKb = privKeys[4]
    for i in range(int(numMessages)):
        dh.DHratchet = dh.SPKb
        IKa = serialize_public(aes.recv(sock,False))
        EKa = serialize_public(aes.recv(sock,False))
        ratchet = serialize_public(aes.recv(sock,False))
        message = aes.recv(sock,False)
        timeStamp = aes.recv(sock)
        userFrom = aes.recv(sock)
        ## Expecting Sender's Public Keys
        dh.x3dh(IKa,EKa)
        # print("SK "+dh.sk.hex())
        dh.init_ratchets()
        msg = dh.decrypt(message,ratchet)
        print("MESSAGE FROM: "+userFrom+" at "+timeStamp+" : "+msg.decode())
        
        
        
def sendMessage(aes,sock,user):
    aes.send("SENDMESSAGE",sock)
    ## Select another user
    valid = False
    while not valid:
        toSend = input("Please enter the username of the user to send a message to")
        aes.send("CHECKUSER:"+toSend,sock)
        status = aes.recv(sock)
        print(status)
        if status == "FOUND":
            valid = True
        else:
            print("User "+toSend+" not found!")
    # When the user is found it prompts the keys to be sent
    ## Get user's recieving keys
    # Keys are in order SPK, IK, OPK
    keys = []
    for i in range(3):
        keys.append(aes.recv(sock,False))
    for counter, key in enumerate(keys):
        keys[counter] = serialize_public(key)
    spk = keys[0]
    ik = keys[1]
    opk = keys[2]
    ## Get message to send
    msg = input("Enter the message to send:\n")
    ## Get User Keys
    privKeys = getPrivKeys(user)
    ## Create Ratchet
    dh = DH_Sender()
    dh.IKa = privKeys[0]
    dh.EKa = privKeys[1]
    dh.x3dh(spk,ik,opk)
    # print("SK "+dh.sk.hex())
    dh.init_ratchets()
    dh.dh_ratchet(spk)
    ct,ratchet = dh.encrypt(msg.encode())
    aes.send(ct,sock)
    aes.send(ratchet,sock)
    ## Send encrypted message to server to hold
    
def getPrivKeys(user):
    '''
    Private keys returned from file 'user.key' in format:
    0: Sender IK, 1: Sender EK, 2: Recv SPK, 3: Recv IK, 4: Recv OPK
    '''
    
    ##TODO: Make this break out of main program safely when file key not found
    privKeys = []
    try:
        with open(user+".key","rb") as f:
            contents = f.read()
        contents = contents.split(b"###")
        for key in contents[:-1]:
            privKeys.append(serialize_private_raw(key))
        return privKeys        
    except FileExistsError:
        print("Unable to find "+user+".key file, it must be in this directory")
        return False
    
    
def connect():
    s = socket.socket()
    s.settimeout(20)
    try:
        s.connect((IP,PORT))
        rsa = RSA()
        encKey = rsa.exchangeKeys(s)
        ## Both client and server should now have three keys each
        aes = AES_Enc()
        rsa.send(aes.getKey(),encKey,s)
        commCheck = aes.recv(s)
        if commCheck == "HELLO":
            print("Established Secure Communication To Server")
            user = login(aes,s)
            if user == False:
                print("Authenticated Failed - Disconnecting")
                return
            un = aes.recv(s)
            print("Login Success: Welcome "+un)
            mainloop(aes,s,user)
            return
        elif commCheck == "FAIL":
            print("Failed to Establish Secure Communication on Client Side - Disconnecting")
            return
        else:
            print("Failed to Establish Secure Communication on Server Side - Disconnecting")
            return
    except ConnectionRefusedError:
        print("SERVER ERROR - Unable to find server at "+IP+":"+str(PORT)+"\nPlease check the server is running")

def login(aes,sock):
    accountExists = input("Do you want to create a new account? (y/N)\n")
    if accountExists.upper()=="Y" or accountExists.upper()=="YES":
        createAccount(aes,sock)
        return login(aes,sock)
    username = input("Enter your username")
    pw = getpass.getpass("Enter your password")
    aes.send("RETURNING USER",sock)
    aes.send("USER:"+username+":USER PW:"+pw+":PW",sock)
    user = aes.recv(sock)
    if user == "NULL":
        user=False
    return user

def createAccount(aes,sock):
    un = input("Enter the username you wish to use\n")
    pw=getpass.getpass("Enter your chosen password\n")
    while pwcheck(pw) == False:
        print("Password must be at least 8 characters, include at least one uppercase, one lowercase and one number")
        pw = getpass.getpass("Enter your chosen password\n")
    pwconfirm = getpass.getpass("Please confirm your password\n")
    if pw!=pwconfirm:
        print("The passwords do not match, returning to Sign In")
        return
    aes.send("NEW USER",sock)
    aes.send("USER:"+un+":USER PW:"+pw+":PW",sock)
    response = aes.recv(sock)
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
                f.write(i+b"###")

        for i in content:
            aes.send(getSendablePubKey(i),sock)
        response = aes.recv(sock)
        print(response)
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
