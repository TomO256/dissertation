from Library import *
import socket
import sqlite3

DEBUG = True

if DEBUG:
    IP = "192.168.0.112"
else:
    IP = "81.109.22.44"

PORT = 2345
def startup():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((IP,PORT))
    s.listen()
    conn, addr = s.accept()
    while True:
        print("Connection at: "+str(addr))
        privKey, pubKey = createKeys()
        encKey = exchangeKeys(pubKey,conn)
        ## Both client and server should now have three keys
        msgToSend = "HELLO"
        check = recv_encrypted_msg(privKey,conn)
        if check!="HELLO":
            msgToSend="FAIL"
        send_encrypted_msg(msgToSend,encKey,conn)
        if check!="HELLO":
            return
        user = checkLogin(privKey,encKey,conn)
        if not user:
            break
        while 1:
            action = recv_encrypted_msg(privKey,conn)
            if action == "SEND":
                store_sent_message(privKey,encKey,conn)
            elif action == "READ":
                forward_stored_message(encKey,conn,user)
            elif action=="EXIT":
                return

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
    db.commit()
    return db,cursor


def addUser(username,password):
    ##TODO: PW check against common db
    db,cursor = init_db()
    users = cursor.execute("SELECT * FROM users").fetchall()
    for user in users:
        if username.upper() == user[0].upper():
            return "Error Creating Account: That username is already taken"
    cursor.execute("INSERT INTO users (username,password) VALUES (?,?)",(username,password,))
    db.commit()
    db.close()
    return "SUCCESS"

def checkLogin(decKey,encKey,socket):
    existing = recv_encrypted_msg(decKey,socket)
    unpw = recv_encrypted_msg(decKey,socket)
    print(unpw)
    un = enclosed(unpw,"USER")
    pw = enclosed(unpw,"PW")
    ## Match against db
    if existing=="NEW USER":
        status = addUser(un,pw)
        send_encrypted_msg(status,encKey,socket)
        return checkLogin(decKey,encKey,socket)
    db,cursor = init_db()
    print(un)
    retrieved = cursor.execute("SELECT * FROM users WHERE UPPER(username)=?",(un.upper(),)).fetchall()
    db.close()
    print(retrieved)
    for i in retrieved:
        ### TODO: Add pw hashing
        if i[0].upper() == un.upper() and i[1] == pw:
            send_encrypted_msg(un,encKey,socket)
            return un
    print("User validation failed")
    send_encrypted_msg("NULL",encKey,socket)
    return False



def store_sent_message(decKey,encKey,socket):
    msg = recv_encrypted_msg(decKey,socket)
    user = enclosed(msg,"FROM")
    to = enclosed(msg,"TO").upper()
    contents = enclosed(msg,"MSG")
    db, cursor = init_db()
    cursor.execute("INSERT INTO messages (username_from, username_to, contents) VALUES(?,?,?)",(user,to,contents))
    db.commit()
    db.close()
    send_encrypted_msg("SUCCESS",encKey,socket)
    return

def forward_stored_message(encKey,socket,user):
    toSend = []
    db, cursor = init_db()
    messages = cursor.execute("SELECT * FROM messages WHERE UPPER(username_to)=?",(user.upper(),)).fetchall()
    db.close()
    for i in messages:
        toSend.append("(FROM "+i[1]+" @ "+i[4]+"): "+i[3])
    count = len(toSend)
    if count==0:
        send_encrypted_msg("END",encKey,socket)
        return
    send_encrypted_msg(str(count),encKey,socket)
    for i in toSend:
        send_encrypted_msg(i,encKey,socket)
# addUser("Tom","Tom")
startup()
