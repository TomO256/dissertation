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
        print("success")
        conn.close()


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
        sendEK TEXT)""")
    db.commit()
    return db,cursor


def addUser(username,password):
    ##TODO: PW check against common db
    db,cursor = init_db()
    users = cursor.execute("SELECT * FROM users").fetchall()
    for user in users:
        if username.upper() == user[0].upper():
            return "Error Creating Account: That username is already taken"
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
    db,cursor = init_db()
    cursor.execute("UPDATE keys SET recvSPK=?, recvIK=?, recvOPK=?, sendIK=?, sendEK=? WHERE UPPER(username)=?",(keys[0],keys[1],keys[2],keys[3],keys[4],username.upper(),))
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

    db,cursor = init_db()
    retrieved = cursor.execute("SELECT * FROM users WHERE UPPER(username)=?",(un.upper(),)).fetchall()
    db.close()
    for i in retrieved:
        if i[0].upper() == un.upper() and check_pw(pw,i[1]):
            rsa.send(un,encKey,socket)
            return un
    print("User validation failed")
    rsa.send("NULL",encKey,socket)
    return False, False




startup()