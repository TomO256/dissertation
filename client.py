from Library import *
import socket
import getpass
import sqlite3

DEBUG = True

if DEBUG:
    test_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    test_socket.connect(("8.8.8.8",80))
    IP = test_socket.getsockname()[0]
    PORT = 2345
    test_socket.close()
else:
    IP = "81.109.22.44"
    PORT = 7579



def menu():
    print("----- M E N U ------")
    print("1.\tSend Message")
    print("2.\tView Messages")
    print("0.\tQuit")
    if DEBUG:
        print("3.\tTERMINATE")
    choice = -1
    try:
        choice = int(input())
    except:
        pass
    options = [0,1,2]
    if DEBUG:
        options.append(3)
    while choice not in options:
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
        elif choice==3:
            print("Terminating Server")
            aes.send("TERMINATE",sock)
            sock.close()
            return
        else:
            print("Closing Secure Connection")
            aes.send("CLOSE",sock)
            sock.close()
            return

def viewMessages(aes,sock,user):
    aes.send("VIEWMESSAGE",sock)
    numMessages = aes.recv(sock)
    print("You have received: "+str(numMessages)+" messages")
    dh = DH_Reciever()
    privKeys = getPrivKeys(user,None)
    dh.IKb = privKeys[2]
    dh.SPKb = privKeys[3]
    for i in range(int(numMessages)):
        dh.DHratchet = dh.SPKb
        encoded_meta = aes.recv(sock,False).split(b"##")
        IKa = serialize_public(encoded_meta[0])
        EKa = serialize_public(encoded_meta[1])
        ratchet = serialize_public(encoded_meta[2])
        message = encoded_meta[3]
        plaintext_meta = aes.recv(sock).split("##")
        timeStamp = plaintext_meta[0]
        userFrom = plaintext_meta[1]
        opk_id = plaintext_meta[2]
        dh.OPKb = get_opk_from_id(user,opk_id)
        ## Expecting Sender's Public Keys
        # print("Sender IKa pub (from server):", pubBytes(IKa))
        # print("Sender EKa pub (from server):", pubBytes(EKa))
        # print("Receiver SPKb pub:", getSendablePubKey(dh.SPKb))
        # print("Receiver IKb  pub:", getSendablePubKey(dh.IKb))
        # print("Receiver OPKb pub:", getSendablePubKey(dh.OPKb))

        dh.x3dh(IKa,EKa)
        # print("SK "+dh.sk.hex())
        dh.init_ratchets()
        msg = dh.decrypt(message,ratchet)
        print("MESSAGE FROM: "+userFrom+" at "+timeStamp+" : "+msg.decode())
        
        
def get_opk_from_id(user,opk_id):
    db = sqlite3.connect(user+"_keys.db")
    cursor = db.cursor()
    opk = cursor.execute("SELECT opk FROM opks WHERE (keyIndex=?)",(opk_id,)).fetchone()
    return serialize_private_raw(opk[0])
def sendMessage(aes,sock,user):
    aes.send("SENDMESSAGE",sock)
    ## Select another user
    valid = False
    while not valid:
        toSend = input("Please enter the username of the user to send a message to")
        aes.send("CHECKUSER:"+toSend,sock)
        status = aes.recv(sock)
        print(status)
        if status.upper() == toSend.upper():
            print("Sending Message to "+status)
            valid = True
        else:
            print("User "+toSend+" not found!")
    # When the user is found it prompts the keys to be sent
    ## Get user's recieving keys
    # Keys are in order SPK, IK, OPK
    keys = []
    for i in range(4):
        keys.append(aes.recv(sock,False))
    for counter, key in enumerate(keys):
        keys[counter] = serialize_public(key)
    keys.append(aes.recv(sock,False))
    spk = keys[0]
    ik = keys[1]
    opk = keys[2]
    ikSign = keys[3]
    signature = keys[4]
    ## Get message to send
    msg = input("Enter the message to send:\n")
    ## Get User Keys

    privKeys = getPrivKeys(user,opk)
    # print("Encrypted using")
    # print(opk.public_bytes(encoding=serialization.Encoding.PEM,
    #                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
    
    ## Create Ratchet
    dh = DH_Sender()
    dh.IKa = privKeys[0]
    dh.EKa = privKeys[1]
    # print("Sender IKa pub:", getSendablePubKey(privKeys[0]))
    # print("Sender EKa pub:", getSendablePubKey(privKeys[1]))
    # print("Using SPK pub:", pubBytes(spk))
    # print("Using IK  pub:", pubBytes(ik))
    # print("Using OPK pub:", pubBytes(opk))

    x = dh.x3dh(spk,ik,opk,ikSign,signature)
    # print(x)
    # print("SK "+dh.sk.hex())
    dh.init_ratchets()
    dh.dh_ratchet(spk)
    ct,ratchet = dh.encrypt(msg.encode())
    aes.send(ct,sock)
    aes.send(ratchet,sock)
    ## Send encrypted message to server to hold
    
def getPrivKeys(user,opk_pub=None):
    '''
    Private keys returned from file 'user.key' in format:
    0: Sender IK, 1: Sender EK, 2: Recv IK, 3: Recv SPK, 4: Recv OPK
    '''
    ##TODO: Make this break out of main program safely when file key not found
    privKeys = []
    db = sqlite3.connect(user+"_keys.db")
    cursor = db.cursor()
    keys = cursor.execute("SELECT * FROM keys").fetchone()
    if opk_pub is not None:
        opks = cursor.execute("SELECT * FROM opks").fetchall()
        opks = list(opks)
        opk = None
        opk_pub = opk_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        for i in opks:
            k = serialize_private_raw(i[1])
            if getSendablePubKey(k)==opk_pub:
                opk = k
                break
        if opk is None:
            raise KeyError
    for key in keys:
        privKeys.append(serialize_private_raw(key))
    if opk_pub:
        privKeys.append(opk)
    return privKeys
    
def connect():
    s = socket.socket()
    s.settimeout(5)
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
                s.close()
                return
            un = aes.recv(s)
            print("Login Success: Welcome "+un)
            mainloop(aes,s,un)
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
def init_db(user):
    db = sqlite3.connect(user+"_keys.db")
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        sendIK BLOB PRIMARY KEY,
        sendEK BLOB,
        recvIK BLOB,
        recvSPK BLOB,
        recvIKSign BLOB)""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS opks(
        keyIndex INTEGER PRIMARY KEY AUTOINCREMENT,
        opk BLOB)""")
    db.commit()
    db.close()
    
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
        # 0: Sender IK, 1: Sender EK, 2: Recv SPK, 3: Recv IK, 5 Recv IKb Sign
        init_db(un)
        content = [sender.IKa,sender.EKa,reciever.SPKb,reciever.IKb,reciever.IKb_sign]
        toWrite=[]
        for item in content:
            toWrite.append(getSendablePrivKey(item))
        opks =[]
        for i in range(100):
            opks.append(reciever.gen_opk())
        db=sqlite3.connect(un+"_keys.db")
        cursor = db.cursor()
        cursor.execute("INSERT INTO keys (sendIK,sendEK,recvSPK,recvIK,recvIKSign) VALUES (?,?,?,?,?)",(toWrite[0],toWrite[1],toWrite[2],toWrite[3],toWrite[4],))
        # with open(un+".key", "wb+") as f:
        #     for i in toWrite:
        #         f.write(i+b"###")
        for i in opks:
            cursor.execute("INSERT INTO opks (opk) VALUES (?)",(getSendablePrivKey(i),))
        db.commit()
        for i in content:
            aes.send(getSendablePubKey(i),sock)
        aes.send(reciever.signature,sock)
        aes.send(str(len(opks)),sock)
        for i in opks:
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
