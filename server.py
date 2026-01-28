from Library import *
import socket
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
        while 1:
            action = recv_encrypted_msg(privKey,conn)
            if action == "SEND":
                store_sent_message(privKey,encKey,conn)
            elif action == "READ":
                forward_stored_message(encKey,conn,addr)
            elif action=="EXIT":
                return

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
startup()