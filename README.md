
# About The Project

It's a Python project that allow to transfer encrypted files between multiple devices on the same network, fast and secure.


![App Screenshot](https://th.bing.com/th/id/R.e005149b9c6d53da75c41dac3de6c3a0?rik=yycaermDerpGHw&riu=http%3a%2f%2fwww.kpbiz.com.au%2fimages%2fcontent-securefiletransfer.jpg&ehk=u3htTM5C%2fefFmXr2XtvVWIqFBEaaVdvQWJz0bcDCfXo%3d&risl=&pid=ImgRaw&r=0)


## Installation

Install my project with 

```bash
  git clone https://github.com/irish1814/Encrypted-Files-Transfer.git
  cd Encrypted-Files-Transfer
```
    
## Dependencies

This project use rsa & pycryptodome module for the encryption part.

```bash
pip install -r requirements.txt
```
## Deployment

The server and client use a 16 bit salt for the AES algorithm, you can find it in the protocol script and replace it with a new random salt of your own using python:

```bash
python3
from Crypto.Random import get_random_bytes
print(get_random_bytes(16))
```

### Deploy Server
server.py & protocol.py needs to be in the same directory!
In the server computer run:
```bash
python3 server.py
```
after running the script, the IP address of the server will be printed on the console.
copy it and enter it when you'll deploy the client.py script

### Deploy Client
client.py & protocol.py needs to be in the same directory!
In the client computer run: 
```bash
python3 client.py
``` 
then enter the IP of the server.
## Technology that have been used in this project

 - [RSA](https://www.geeksforgeeks.org/rsa-algorithm-cryptography/)
 - [AES Encryption](https://www.geeksforgeeks.org/advanced-encryption-standard-aes/)
 - [Socket in Computer Networking](https://www.geeksforgeeks.org/socket-in-computer-network/)


## Authors

- [@irish1814](https://www.github.com/irish1814)
