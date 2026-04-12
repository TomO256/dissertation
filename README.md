# SbD and MS Copilot Implementation of Client-Server Message Service
This is a demonstration project of two programatic examples, providing a service
of exchanging messages between clients built using two different techniques: 
Security by Design and Generative Artificial Intelligence.
<br>
Both services provide a messaging service between clients, both on a single network, and across the internet. The below steps explain how the program can be setup and run in either instance. 

### Security
Through a security review and evaluation, the Secure by Design approach is deemed to be more secure and sending and recieving data. It is not recommended to use the copilot created code outside of demonstration due to security concerns.

To protect your own personal information, it is not recommended to use a real name as a username, nor transfer any personal information over the network, depsite the high level of encryption used. This is built as a demonstration project for comparison, rather than a release-ready messaging client.

## Installation
- Clone the repository <br>
```git clone https://github.com/TomO256/dissertation.git``` <br>
- Move into the directory <br>
```cd dissertation``` 
- Create a python virtual environment <br>
```python -m venv venv```
- Install the necessary requirements <br>
```pip install -r requirements.txt```

## Running

### Running the Security by Design approach
#### On the same machine (debug mode)
1. In ```client.py``` and `server.py` set the `DEBUG` variable (`client.py` -line 8, `server.py` - line 6) to `True`
2. Run the server: `python server.py`
3. Run the client: `python client.py`

#### On the same local network

1. In ```client.py``` and `server.py` set the `DEBUG` variable (`client.py` -line 8, `server.py` - line 6) to `False`
2. In ```client.py``` line 17, set variable `IP` to the local IP address of the server. (Can be found by running `ipconfig` (windows) or `ifconfig` (linux) on the server)
3. Ensure the `Library.py` file exists on both the client and the server.
4. Run the server: `python server.py` 
5. Run the client: `python client.py`

#### Over the internet

1. In ```client.py``` and `server.py` set the `DEBUG` variable (`client.py` -line 8, `server.py` - line 6) to `False`
2. In ```client.py``` line 17, set variable `IP` to the public IP address of the server. (Can be found by running `curl canhazip.com` or searching [whatismyipaddress.com](https://whatismyipaddress.com/) on the server network)
3. Ensure the `Library.py` file exists on both the client and the server.
4. Set up port forwarding to forward port 7579 to the local IP address of the server. This is easiest to do by accessing the router configuration settings on the server's network, often found at: [192.168.0.1](http://192.168.0.1/). If port 7579 is used by another service on the network, the port can be specified through the variable `PORT` in both the client and server.
5. Run the server: `python server.py`
6. Run the client: `python client.py`

### Running the Generative AI approach
#### Over the local network (including same machine)
1. On the server side, create a user, by specifying a username and password in file `copilot_create_user.py`, and running the file: `python copilot_create_client.py`.
2. Create a certifcate for the server if one does not already exist<br>
`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`
3. On the client side, set the variable `HOST` to the local IP address of the server (can be found by running `ipconfig` (windows) or `ifconfig` (linux) on the server)
4. Run the server: `python copilot_server.py`
5. Run the client: `python copilot_client.py`

#### Over the internet
1. On the server side, create a user, by specifying a username and password in file `copilot_create_user.py`, and running the file: `python copilot_create_client.py`.
2. Create a certifcate for the server if one does not already exist<br>
`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`
3. Set up port forwarding to forward port 7580 to the local IP address of the server. This is easiest to do by accessing the router configuration settings on the server's network, often found at: [192.168.0.1](http://192.168.0.1/). If port 7580 is used by another service on the network, the port can be specified through the variable `PORT` in both the client and server.
4. In `copilot_client.py` set the variable `HOST` to the public IP address of the server (Can be found by running `curl canhazip.com` or searching [whatismyipaddress.com](https://whatismyipaddress.com/) on the server network)
5. Run the server: `python copilot_server.py`
6. Run the client: `python copilot_client.py`