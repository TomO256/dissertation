# Cloud Storage Client (Secure By Design)
### TODO: CRITICAL - does not show sender when msg recv - Done
## TODO: Add usernames to prevent IP issues
## TODO: Protect against injection attacks of un/pw
## TODO: Graceful exiting
## TODO: Connect messages with database

import socket
from Library import *
import getpass

DEBUG = True

if DEBUG:
    IP = socket.gethostbyname(socket.gethostname())
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

def send_message(decKey,encKey,socket,user):
    ## TODO: Validation
    ## TODO: Add user lookup table

    # Get IP of user to send to
    to_send = input("Enter the user to send the message to\n")
    # Get Message
    msg = input("Enter your message")
    # Send Message to Server
    send_encrypted_msg("SEND",encKey,socket)
    send_encrypted_msg("TO:"+to_send+":TO MSG:"+msg+":MSG"+" FROM:"+user+":FROM",encKey,socket)
    recv_encrypted_msg(decKey,socket)
    return

def check_message(decKey,encKey,socket):
    # Prompt server to send messages
    # Probably do this by requesting message count, then iterating for those messages
    send_encrypted_msg("READ",encKey,socket)
    count = recv_encrypted_msg(decKey,socket)
    if count=="END":
        print("NO MESSAGES FOUND ON SERVER")
        return []
    msgs = []
    for i in range(int(count)):
        msgs.append(recv_encrypted_msg(decKey,socket))
    return msgs

def mainloop(decKey,encKey,sock,user):
    action = menu()
    if action=="1":
        send_message(decKey,encKey,sock,user)
    elif action=="2":
        msgs = check_message(decKey,encKey,sock)
        for counter,i in enumerate(msgs):
            print("Message "+str(counter+1)+": "+i)
    mainloop(decKey,encKey,sock,user)

def pwcheck(password):
    if len(password) < 8:
        return False
    if password.upper() == password:
        return False
    if password.lower() == password:
        return False
    digit = any([i.isdigit() for i in password])
    if not digit:
        return False
    return True
    

def createAccount(decKey,encKey,sock):
    un = input("Enter the username you wish to use\n")
    pw=getpass.getpass("Enter your chosen password\n")
    while pwcheck(pw) == False:
        print("Password must be at least 8 characters, include at least one uppercase, one lowercase and one number")
        pw = getpass.getpass("Enter your chosen password\n")
    pwconfirm = getpass.getpass("Please confirm your password\n")
    if pw!=pwconfirm:
        print("The passwords do not match, returning to Sign In")
        return
    send_encrypted_msg("NEW USER",encKey,sock)
    send_encrypted_msg("USER:"+un+":USER PW:"+pw+":PW",encKey,sock)
    response = recv_encrypted_msg(decKey,sock)
    if response == "SUCCESS":
        print("Account Created Succesfully, returning to Sign In")
        return
    else:
        print(response)
        print("Returning to Sign In")
        return

def login(decKey,encKey,sock):
    accountExists = input("Do you want to create a new account? (y/N)\n")
    if accountExists.upper()=="Y" or accountExists.upper()=="YES":
        createAccount(decKey,encKey,sock)
        return login(decKey,encKey,sock)
    username = input("Enter your username")
    pw = getpass.getpass("Enter your password")
    send_encrypted_msg("RETURNING USER",encKey,sock)
    send_encrypted_msg("USER:"+username+":USER PW:"+pw+":PW",encKey,sock)
    user = recv_encrypted_msg(decKey,sock)
    if user == "NULL":
        user=False
    return user

def connect():
    s = socket.socket()
    s.settimeout(20)
    try:
        s.connect((IP,PORT))
        privKey,  pubKey = createKeys()
        encKey = exchangeKeys(pubKey,s)
        ## Both client and server should now have three keys each
        send_encrypted_msg("HELLO",encKey,s)
        commCheck = recv_encrypted_msg(privKey,s)
        if commCheck == "HELLO":
            print("Established Secure Communication To Server")
            user = login(privKey,encKey,s)
            if user == False:
                print("Authenticated Failed - Disconnecting")
                return
            mainloop(privKey,encKey,s,user)
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
