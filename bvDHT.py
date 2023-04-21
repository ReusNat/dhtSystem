from socket import *
from sys import argv
import threading
import hashlib

# int(hasedKey, base=16) <- gets the int version of the digest

def getLine(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()

def updatePeerList():
    pass

#inputs the non-encrypted Key.
#returns closest peer's userID without a new line... str(ip) + ":" + str(port)
def closestAlgorithim(key):
    hashedKey = hashlib.sha224(key.encode()).hexdigest()
    listy = knownPeers.items()
    end = listy[0]
    for peer in listy:
        if peer[0] < hashedKey and peer[0] > end[0]:
            end = peer
    if end == listy[0]:
        if listy[0][0] > hashedKey:
            end = listy[-1]
    connTuple = (end[1], int(end[2]))
    val = str(end[1]) + ":" + str(end[2])
    while True:
        clientSock = socket(AF_INET, SOCK_STREAM)
        clientSock.connect( conn_Tuple )
        val = closestPeer(clientSocket)
        splitVal = val.split(":")
        if (splitVal[0],splitVal[1]) == connTuple:
            break
        connTuple = (splitVal[0],splitVal[1])
    return val

#so this works basically by looking through all of our knownPeers list, which should include us.
# for each peer in our known peers
#  check if that peer's ID is less than the hashedKey and greater than the last closest id.
#  if thats the case, change the last closest id to the current
#  otherwise continue
# now if at the end the closest peer is the first, we check if it's actually larger than the ID. If it is, than we know the previous person is actually the holder of that ID
# thus, we loop back around to the last peer in our list and return that peer's USERID

###TODO:Note if knownPeers list does not contain ourselves than we need to include us in the search below explictly. ####
def closestRecv(sockRecv):
    hashedKey = getline(sock)
    listy = knownPeers.items()
    end = listy[0]
    for peer in listy:
        if peer[0] < hashedKey and peer[0] > end[0]:
            end = peer
    if end == listy[0]:
        if listy[0][0] > hashedKey:
            end = listy[-1]
    sockRecv.send (str(end[1]) + ":" + (str(end[2]))  + "\n" )

def closestPeer(hashedpos, connInfo):
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
    elif conform == 'FU':
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

def handle_client(connInfo, commandDictionary):
    sock = connInfo[0]
    command = sock.recv(12).decode()
    commandDictionart[command]

if len(argv) < 3:
    exit('Not enough arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')
elif len(argv) > 3:
    exit('Too many arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')

ourIP = argv[1]
ourPort = argv[2]
ourID = f'{ourIP}:{ourPort}'

data = {}
nextID = ''

#clientID = clientIP:clientPort>
clientID = input('Client ID: ')
known_peers = [clientID]
clientIP, clientPort = clientID.split(':')
#clientSock = socket(AF_INET, SOCK_STREAM)
#clientSock.connect( (clientIP, int(clientPort)) )

print(f'{ourID=}')
print(f'{known_peers[0]=}')

# Listening Socket
listener = socker(AF_INET, SOCK_STREAM)
listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
listener.bind( ('', ourPort) )
listener.listen(32)

running = True
while running:
    try:
        threading.Thread(target=handleClient, args=(listener.accept(), commandDict,), daemon=True).start()
    except KeyboardInterrupt:
        running = False
