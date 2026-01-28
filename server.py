from Library import *
import socket
import sqlite3

DEBUG = True

if DEBUG:
    IP = "10.41.61.156"
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
        status = checkLogin(privKey,encKey,conn)
        if not status:
            break
        while 1:
            action = recv_encrypted_msg(privKey,conn)
            if action == "SEND":
                store_sent_message(privKey,encKey,conn)
            elif action == "READ":
                forward_stored_message(encKey,conn,addr)
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
    db,cursor = init_db()
    cursor.execute("INSERT INTO users (username,password) VALUES (?,?)",(username.upper(),password,))
    db.commit()
    db.close()

def checkLogin(decKey,encKey,socket):
    unpw = recv_encrypted_msg(decKey,socket)
    print(unpw)
    un = enclosed(unpw,"USER").upper()
    pw = enclosed(unpw,"PW")
    ## Match against db

    db,cursor = init_db()
    print(un)
    retrieved = cursor.execute("SELECT * FROM users WHERE username=?",(un,)).fetchall()
    db.close()
    print(retrieved)
    for i in retrieved:
        ### TODO: Add pw hashing
        if i[0] == un.upper() and i[1] == pw:
            send_encrypted_msg(un,encKey,socket)
            return un
    print("User validation failed")
    send_encrypted_msg("NULL",encKey,socket)
    return False



def store_sent_message(decKey,encKey,socket):
    msg = recv_encrypted_msg(decKey,socket)
    with open("msgs.txt","a") as f:
        f.write(msg+"\n")
    send_encrypted_msg("SUCCESS",encKey,socket)
    return

def forward_stored_message(encKey,socket,addr):
    toSend = []
    with open("msgs.txt","r") as f:
        for l in f:
            # print("checking "+enclosed(l,"IP")+" against "+str(addr[0]))
            if enclosed(l,"IP") == str(addr[0]):
                # print("success")
                toSend.append("(FROM "+enclosed(l,"FROM")+"): "+enclosed(l,"MSG"))
    count = len(toSend)
    if count==0:
        send_encrypted_msg("END",encKey,socket)
        return
    send_encrypted_msg(str(count),encKey,socket)
    for i in toSend:
        send_encrypted_msg(i,encKey,socket)
# addUser("Tom","Tom")
startup()
