# Cloud Storage Client (Secure By Design)
import socket
from Library import *

DEBUG = True

if DEBUG:
    IP = "10.41.61.156"
else:
    IP = "81.109.22.44"
PORT = 2345

    
def menu():
    print("1. Send Message")
    print("2. Check Messages")
    print("9. Exit")
    opt = "-1"
    while opt not in ["9","1","2"]:
        opt = str(input("Select an Option\n"))
    return opt

def send_message(decKey,encKey,socket):
    ## TODO: Validation
    ## TODO: Add user lookup table

    # Get IP of user to send to
    to_send = input("Enter the IP to send the message to\n")
    # Get Message
    msg = input("Enter your message")
    # Send Message to Server
    send_encrypted_msg("SEND",encKey,socket)
    send_encrypted_msg("IP:"+to_send+":IP MSG:"+msg+":MSG",encKey,socket)
    recv_encrypted_msg(decKey,socket)
    return

def check_message():
    # Prompt server to send messages
    # Probably do this by requesting message count, then iterating for those messages
    return

def mainloop(decKey,encKey,sock):
    action = menu()
    if action=="1":
        send_message(decKey,encKey,sock)
    elif action=="2":
        check_message()


def connect():
    s = socket.socket()
    s.settimeout(10)
    try:
        s.connect((IP,PORT))
        privKey,  pubKey = createKeys()
        encKey = exchangeKeys(pubKey,s)
        ## Both client and server should now have three keys each
        send_encrypted_msg("HELLO",encKey,s)
        commCheck = recv_encrypted_msg(privKey,s)
        if commCheck == "HELLO":
            print("Established Secure Communication To Server")
            mainloop(privKey,encKey,s)
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
