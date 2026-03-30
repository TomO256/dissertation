from final_lib import RSA, enclosed, AES_Enc
import socket,bcrypt,sqlite3,time

DEBUG = True
test_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
test_socket.connect(("8.8.8.8",80))
if DEBUG:
    IP = test_socket.getsockname()[0]
    PORT = 2345
test_socket.close()
if not DEBUG:
    IP = "0.0.0.0"
    PORT = 7579
print("Running on: "+IP+":"+str(PORT))



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
        aes_key = rsa.recv(conn)
        aes = AES_Enc(aes_key)
        aes.send("HELLO",conn)
        user = checkLogin(aes,conn)
        aes.send(user,conn)
        operation = None
        while operation!="CLOSE":
            operation = aes.recv(conn)
            if operation=="SENDMESSAGE":
                handleSend(aes,user,conn)
            elif operation=="VIEWMESSAGE":
                handleView(aes,user,conn)
            else:
                print("Unknown Action")
        conn.close()

def handleView(aes,user,conn):
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    messages = cursor.execute("SELECT * FROM messages WHERE username_to=?",(user,)).fetchall()
    count = len(messages)
    aes.send(str(count),conn)
    for msg in messages:
        keys = cursor.execute("SELECT sendIK, sendEK FROM keys WHERE username=?",(msg[1],)).fetchone()
        aes.send(keys[0]+b"##"+keys[1]+b"##"+msg[4]+b"##"+msg[3],conn)
        aes.send(msg[5]+"##"+msg[1],conn)


def handleSend(aes,user,conn):
    valid = False
    while not valid:
        toCheck = aes.recv(conn)
        userTo = toCheck.split(":")[1]
        if existingUser(userTo):
            aes.send("FOUND",conn)
            valid = True
        else:
            aes.send("NOT FOUND",conn)
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    keys = cursor.execute("SELECT recvSPK, recvIK, recvOPK FROM keys WHERE UPPER(username)=?",(userTo.upper(),)).fetchone()
    for i in keys:
        aes.send(i,conn)
    msg = aes.recv(conn,False)
    ratchet = aes.recv(conn,False)
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    cursor.execute("INSERT INTO messages (username_from,username_to,contents,ratchet) VALUES (?,?,?,?)",(user,userTo,msg,ratchet))
    db.commit()
    db.close()
    
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

def addUserPubKey(username,aes,socket):
    keys=[]
    for i in range(5):
        keys.append(aes.recv(socket,False))
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


def checkLogin(aes,socket):
    existing = aes.recv(socket)
    unpw = aes.recv(socket)
    un = enclosed(unpw,"USER")
    pw = enclosed(unpw,"PW")
    ## Match against db
    if existing=="NEW USER":
        status = addUser(un,pw)
        aes.send(status,socket)
        addUserPubKey(un,aes,socket)
        aes.send("Public Keys Uploaded Successfully",socket)
        return checkLogin(aes,socket)
        
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    retrieved = cursor.execute("SELECT * FROM users WHERE UPPER(username)=?",(un.upper(),)).fetchall()
    db.close()
    for i in retrieved:
        if i[0].upper() == un.upper() and check_pw(pw,i[1]):
            aes.send(un,socket)
            return i[0]
    print("User validation failed")
    aes.send("NULL",socket)
    return checkLogin(aes,socket)
    
startup()