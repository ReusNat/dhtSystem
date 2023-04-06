from socket import *
from sys import argv
import threading
import hashlib

# hashedKey = hashlib.sha224(key.encode()).hexdigest()
# int(hasedKey, base=16) <- gets the int version of the digest

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()


if len(argv) < 3:
    exit('Not enough arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')
elif len(argv) > 3:
    exit('Too many arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')

ourIP = argv[1]
ourPort = argv[2]
ourID = f'{ourIP}:{ourPort}'

data = {}
nextID = ''

#<clientIP>:<clientPort> 
clientID = input('Client ID: ')
known_peers = [clientID]
clientIP, clientPort = clientID.split(':')
#clientSock = socket(AF_INET, SOCK_STREAM)
#clientSock.connect( (clientIP, int(clientPort)) )

print(f'{ourID=}')
print(f'{known_peers[0]=}')

def closest_peer(hashedpos, connInfo):
    sock, sockAddress = connInfo
    sock.send('CLOSEST_PEER'.encode())
    sock.send(hashedpos)
    return getline(sock)

def join(hashedpos, connInfo):
    global nextID
    sock, sockAddress = connInfo
    sock.send('JOIN_DHT_NOW'.encode())
    sock.send(ourID.encode())
    nextID = getline(connInfo)
    numFiles = getline(connInfo)
    
    for i in range(0,numFiles):
        fileHashPos = getline(connInfo)
        fileSize = int(getline(connInfo).rstrip())
        fileBytes = sock.recv(fileSize)
        data[fileHashPos] = fileBytes
    update_peer(ourID)
    sock.send('ok'.encode())

def leave(connInfo):
    sock, sockAddress = connInfo
    sock.send('TIME_2_SPLIT'.encode())
    sock.send( (str(len(data) + '\n').encode()) )
    for hashPos in data:
        sock.send(hashPos)
        sock.send(len(data[hashPos]))
        sock.send(data[hasPos])

    conform = sock.recv(2).decode()
    if conform == 'ok':
        return
    elif conform == 'fu':
        while conform != 'ok':
            for hashPos in data:
                sock.send(hashPos)
                sock.send(len(data[hashPos]))
                sock.send(data[hasPos])
            conform = sock.recv(2).decode()

def update_peer(connInfo):
    sock = connInfo[0]
    sock.send('UPDATE_PEER_'.encode())
    sock.send(ourID.encode())
    if sock.recv(2).decode() != 'ok':
        while sock.recv(2).decode() != 'ok':
            sock.send(ourID.encode())


def contains(hashPos, connInfo):
    sock = connInfo[0]
    sock.send('CONTAIN_FILE'.encode())
    sock.send(hashPos.encode())
    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    
    return True

def get_data(hashPos, connInfo):
    sock = connInfo[0]
    sock.send('GET_DATA_NOW'.encode())
    sock.send(hashPos)
    confirm = sock.recv(2)
    if confirm == 'FU':
        return None
    confirm = sock.recv(2)
    if confirm == 'FU':
        return None
    
    numBytes = getline(connInfo)
    return sock.recv(int(numBytes.rstrip()))

def insert(hashPos, connInfo, fileBytes):
    sock = connInfo[0]
    sock.send('INSERT_FILE!'.encode())
    sock.send(hashPos)
    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    
    sock.send( (str(len(fileBytes)) + '\n').encode())
    sock.send(fileBytes)

    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    return True

def delete(hashPos, connInfo):
    sock = connInfo[0]
    sock.send('DELETE_FILE!'.encode())
    sock.send(hashPos.encode())
    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    
    return True

def handle_client(connInfo):
    pass


