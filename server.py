from Library import RSA, enclosed, AES_Enc
import socket,bcrypt,sqlite3,time,threading,functools,os

DEBUG = True

if DEBUG:
    test_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    test_socket.connect(("8.8.8.8",80))
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
        t = threading.Thread(target=functools.partial(mainloop,conn,addr))
        t.start()

def mainloop(conn,addr):
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
        elif operation=="TERMINATE" and DEBUG==True:
            os._exit(1)
    print("Connection with "+str(addr)+" closed")
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
        aes.send(msg[5]+"##"+msg[1]+"##"+str(msg[6]),conn)
        time.sleep(0.1)


def handleSend(aes,user,conn):
    valid = False
    while not valid:
        toCheck = aes.recv(conn)
        userTo = toCheck.split(":")[1]
        userTo = existingUser(userTo)
        if userTo:
            aes.send(userTo,conn)
            valid = True
        else:
            aes.send("NOT FOUND",conn)
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    opk = cursor.execute("SELECT opk_id, opk FROM opks WHERE UPPER(username)=?",(userTo.upper(),)).fetchone()
    keys = cursor.execute("SELECT recvSPK, recvIK,recvIKSign,recvSignature FROM keys WHERE UPPER(username)=?",(userTo.upper(),)).fetchone()
    keys = list(keys)
    keys.insert(2,opk[1])
    for i in keys:
        aes.send(i,conn)
    msg = aes.recv(conn,False)
    ratchet = aes.recv(conn,False)
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    cursor.execute("INSERT INTO messages (username_from,username_to,contents,ratchet,opk_id) VALUES (?,?,?,?,?)",(user,userTo,msg,ratchet,opk[0],))
    cursor.execute("DELETE FROM opks WHERE username=? AND opk_id=?",(user,opk[0],))
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
        opk_id INTEGER,
        FOREIGN KEY (username_from) REFERENCES users(username),
        FOREIGN KEY (username_to) REFERENCES users(username),
        FOREIGN KEY (opk_id) REFERENCES opks(opk_id)
        )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        username TEXT UNIQUE PRIMARY KEY,
        recvSPK TEXT,
        recvIK TEXT,
        recvIKSign TEXT,
        recvSignature TEXT,
        sendIK TEXT,
        sendEK TEXT,
        FOREIGN KEY (username) REFERENCES users(username))""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS opks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        opk_id INTEGER,
        opk BLOB)""")
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
            return user[0]
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
    for i in range(6):
        keys.append(aes.recv(socket,False))
    numOpks = int(aes.recv(socket))
    opks=[]
    for i in range(numOpks):
        opks.append(aes.recv(socket,False))
    #Order is:
    # 0: Sender IK, 1: Sender EK, 2: Recv SPK, 3: Recv IK, 4: Recv IKb Sign, 5: Signature
    db = sqlite3.connect("Server.db")
    cursor = db.cursor()
    cursor.execute("UPDATE keys SET recvSPK=?, recvIK=?,recvIKSign=?, recvSignature=?, sendIK=?, sendEK=? WHERE UPPER(username)=?",(keys[2],keys[3],keys[4],keys[5],keys[0],keys[1],username.upper(),))
    for i in range(1,len(opks)+1):
        cursor.execute("INSERT INTO opks (username,opk_id,opk) VALUES (?,?,?)",(username,i,opks[i-1]))
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
        if status!="SUCCESS":
            return checkLogin(aes,socket)
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
    socket.close()
    return
    
startup()