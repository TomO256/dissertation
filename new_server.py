from new_lib import RSA
import socket

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
    conn, addr = s.accept()
    while True:
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
        # user,encKey = checkLogin(privKey,encKey,conn)
        print("success")
        # if not user:
        #     break

startup()