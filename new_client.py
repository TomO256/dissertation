from new_lib import RSA
import socket

DEBUG = True

if DEBUG:
    IP = socket.gethostbyname(socket.gethostname())
    IP = "10.41.63.155"
else:
    IP = "81.109.22.44"

PORT = 2345

def login(x,y,z):
    print("working :)")
    return False

def connect():
    s = socket.socket()
    s.settimeout(20)
    try:
        s.connect((IP,PORT))
        rsa = RSA()
        encKey = rsa.exchangeKeys(s)
        ## Both client and server should now have three keys each
        rsa.send("HELLO",encKey,s)
        commCheck = rsa.recv(s)
        if commCheck == "HELLO":
            print("Established Secure Communication To Server")
            user = login("","","")
            if user == False:
                print("Authenticated Failed - Disconnecting")
                return
            # mainloop(privKey,encKey,s,user)
            return
        elif commCheck == "FAIL":
            print("Failed to Establish Secure Communication on Client Side - Disconnecting")
            return
        else:
            print("Failed to Establish Secure Communication on Server Side - Disconnecting")
            return
    except ConnectionRefusedError:
        print("SERVER ERROR - Unable to find server at "+IP+":"+str(PORT)+"\nPlease check the server is running")
connect()
