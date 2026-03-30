from new_lib import RSA, enclosed
import socket,bcrypt,sqlite3

DEBUG = True
test_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
test_socket.connect(("8.8.8.8",80))
IP = test_socket.getsockname()[0]
test_socket.close()
print("Running on: "+IP)


PORT = 2345
def startup():
    init_db()
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((IP,PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        print("Connection at: "+str(addr))
        rsa = RSA()
        encKey = rsa.exchangeKeys(conn)
        ## Both client and server should now have three keys
        msgToSend = "HELLO"
        check = rsa.recv(conn)
        if check!="HELLO":
            msgToSend="FAIL"
        rsa.send(msgToSend,encKey,conn)
        if check!="HELLO":
            return
        user = checkLogin(rsa,encKey,conn)
        rsa.send(user,encKey,conn)
        operation = None
        while operation!="CLOSE":
            operation = rsa.recv(conn)
            if operation=="SENDMESSAGE":
                handleSend(rsa,user,encKey,conn)
            elif operation=="VIEWMESSAGE":
                handleView(rsa,user,encKey,conn)
            else:
                print("Unknown Action")
        conn.close()

def handleView(rsa,user,encKey,conn):
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    print(user)
    messages = cursor.execute("SELECT * FROM messages WHERE username_to=?",(user,)).fetchall()
    count = len(messages)
    rsa.send(str(count),encKey,conn)
    for msg in messages:
        keys = cursor.execute("SELECT sendIK, sendEK FROM keys WHERE username=?",(msg[1],)).fetchone()
        rsa.send(keys[0],encKey,conn)
        rsa.send(keys[1],encKey,conn)
        rsa.send(msg[4],encKey,conn)
        rsa.send(msg[3],encKey,conn)
        rsa.send(msg[5],encKey,conn)
        rsa.send(msg[1],encKey,conn)


def handleSend(rsa,user,rsaEncKey,conn):
    valid = False
    while not valid:
        toCheck = rsa.recv(conn)
        userTo = toCheck.split(":")[1]
        if existingUser(userTo):
            rsa.send("FOUND",rsaEncKey,conn)
            valid = True
        else:
            rsa.send("NOT FOUND",rsaEncKey,conn)
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    keys = cursor.execute("SELECT recvSPK, recvIK, recvOPK FROM keys WHERE UPPER(username)=?",(userTo.upper(),)).fetchone()
    for i in keys:
        rsa.send(i,rsaEncKey,conn)
    msg = rsa.recv(conn,False)
    ratchet = rsa.recv(conn,False)
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    cursor.execute("INSERT INTO messages (username_from,username_to,contents,ratchet) VALUES (?,?,?,?)",(user,userTo,msg,ratchet))
    db.commit()
    db.close()
    print("WOOOOOOO")
    
def init_db():
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT UNIQUE PRIMARY KEY,
        password TEXT)""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username_from TEXT,
        username_to TEXT,
        contents TEXT,
        ratchet TEXT,
        sent DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username_from) REFERENCES users(username),
        FOREIGN KEY (username_to) REFERENCES users(username)
        )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        username TEXT UNIQUE PRIMARY KEY,
        recvSPK TEXT,
        recvIK TEXT,
        recvOPK TEXT,
        sendIK TEXT,
        sendEK TEXT,
        FOREIGN KEY (username) REFERENCES users(username))""")
    db.commit()
    db.close()
    return True

def existingUser(username):
    # print("Trying to find "+username+" in the db")
    ## Check if a user exists in the database
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    usrs = cursor.execute("SELECT * FROM users").fetchall()
    for user in usrs:
        if username.upper() == user[0].upper():
            return True
    db.close()
    return False

def addUser(username,password):
    ##TODO: PW check against common db
    if existingUser(username):
        return "Error Creating Account: That username is already taken"
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    password = hash_pw(password)
    cursor.execute("INSERT INTO users (username,password) VALUES (?,?)",(username,password,))
    cursor.execute("INSERT INTO keys (username) VALUES (?)",(username,))
    db.commit()
    db.close()
    return "SUCCESS"

def addUserPubKey(username,rsa,socket):
    keys=[]
    for i in range(5):
        keys.append(rsa.recv(socket,False))
    #Order is:
    # 0: Sender IK, 1: Sender EK, 2: Recv SPK, 3: Recv IK, 4: Recv OP
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    cursor.execute("UPDATE keys SET recvSPK=?, recvIK=?, recvOPK=?, sendIK=?, sendEK=? WHERE UPPER(username)=?",(keys[2],keys[3],keys[4],keys[0],keys[1],username.upper(),))
    db.commit()
    db.close()

def hash_pw(password):
    return bcrypt.hashpw(password.encode(),bcrypt.gensalt())

def check_pw(plaintext,hashed_pw):
    return bcrypt.checkpw(plaintext.encode(),hashed_pw)


def checkLogin(rsa,encKey,socket):
    existing = rsa.recv(socket)
    unpw = rsa.recv(socket)
    un = enclosed(unpw,"USER")
    pw = enclosed(unpw,"PW")
    ## Match against db
    if existing=="NEW USER":
        status = addUser(un,pw)
        rsa.send(status,encKey,socket)
        addUserPubKey(un,rsa,socket)
        rsa.send("Public Keys Uploaded Successfully",encKey,socket)
        return checkLogin(rsa,encKey,socket)
        
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    retrieved = cursor.execute("SELECT * FROM users WHERE UPPER(username)=?",(un.upper(),)).fetchall()
    db.close()
    for i in retrieved:
        if i[0].upper() == un.upper() and check_pw(pw,i[1]):
            rsa.send(un,encKey,socket)
            return i[0]
    print("User validation failed")
    rsa.send("NULL",encKey,socket)
    return checkLogin(rsa,encKey,socket)
    




startup()