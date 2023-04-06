from socket import *
from sys import argv
import threading
import hashlib

# hashedKey = hashlib.sha224(key.encode()).hexdigest()
# int(hasedKey, base=16) <- gets the int version of the digest


if len(a) < 3:
    exit('Not enough arguments\nUsage: python3 bvDHT.py <IP> <port>')
elif len(a) > 3:
    exit('Too many arguments\nUsage: python3 bvDHT.py <IP> <port>')

clientIP = argv[1]
clientPort = argv[2]

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect( (clientIP, clientPort) )


