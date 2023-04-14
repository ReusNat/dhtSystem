from socket import *
from sys import argv
import threading
import hashlib


def getline(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()


def closestPeerSend(hashedPos, connInfo):
    sock, sockAddress = connInfo
    sock.send('CLOSEST_PEER'.encode())
    sock.send(hashedPos)
    return getline(sock)


def closestPeerRecv(connInfo):
    pass


def joinSend(hashedPos, connInfo):
    global nextID
    sock, sockAddress = connInfo
    sock.send('JOIN_DHT_NOW'.encode())
    sock.send(ourID.encode())
    nextID = getline(connInfo)
    numFiles = getline(connInfo)

    for i in range(0, numFiles):
        fileHashPos = getline(connInfo)
        fileSize = int(getline(connInfo).rstrip())
        fileBytes = sock.recv(fileSize)
        data[fileHashPos] = fileBytes
    updatePeerSend(ourID)
    sock.send('ok'.encode())


def joinRecv(hashedPos, connInfo):
    pass


def leaveSend(connInfo):
    sock, sockAddress = connInfo
    sock.send('TIME_2_SPLIT'.encode())
    sock.send((str(len(data) + '\n').encode()))
    for hashPos in data:
        sock.send(hashPos)
        sock.send(len(data[hashPos]))
        sock.send(data[hashPos])

    conform = sock.recv(2).decode()
    if conform == 'ok':
        return
    elif conform == 'FU':
        while conform != 'ok':
            for hashPos in data:
                sock.send(hashPos)
                sock.send(len(data[hashPos]))
                sock.send(data[hashPos])
            conform = sock.recv(2).decode()


def leaveRecv(connInfo):
    pass


def updatePeerSend(connInfo):
    sock = connInfo[0]
    sock.send('UPDATE_PEER_'.encode())
    sock.send(ourID.encode())
    if sock.recv(2).decode() != 'ok':
        while sock.recv(2).decode() != 'ok':
            sock.send(ourID.encode())


def updatePeerRecv(connInfo):
    pass


def containsSend(hashPos, connInfo):
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


def containsRecv(connInfo):
    pass


def getDataSend(hashPos, connInfo):
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


def getDataRecv(connInfo):
    pass


def insertSend(hashPos, connInfo, fileBytes):
    sock = connInfo[0]
    sock.send('INSERT_FILE!'.encode())
    sock.send(hashPos)
    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False

    sock.send((str(len(fileBytes)) + '\n').encode())
    sock.send(fileBytes)

    confirm = sock.recv(2).decode()
    if confirm == 'FU':
        return False
    return True


def insertRecv(connInfo):
    sock = connInfo[0]
    hashPos = int(sock.recv(56).decode(), base=10)
    if closestPeerSend(connInfo, hashPos) == fingerTable['me']:
        sock.send('OK'.encode())
        fileSize = int(getline(sock))
        try:
            data[hashPos] = sock.recv(fileSize)
            sock.send('OK'.encode())
            sock.close()
        except Exception:
            sock.send('FU'.encode())
            sock.close()
    else:
        sock.send('FU'.encode())


def deleteSend(hashPos, connInfo):
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


def deleteRecv(connInfo):
    pass


def handleClient(connInfo):
    commandDictionary = {
                'CLOSEST_PEER': closestPeerRecv,
                'JOIN_DHT_NOW': joinRecv,
                'TIME_2_SPLIT': leaveRecv,
                'INSERT_FILE!': insertRecv,
                'DELETE_FILE!': deleteRecv,
                'CONTAIN_FILE': containsRecv,
                'GET_DATA_NOW': getDataRecv,
                'UPDATE_PEER_': updatePeerRecv
    }
    sock = connInfo[0]
    command = sock.recv(12).decode()
    commandDictionary[command](connInfo)


if len(argv) < 3:
    exit('Not enough arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')
elif len(argv) > 3:
    exit('Too many arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')

ourIP = argv[1]
ourPort = argv[2]
ourID = f'{ourIP}:{ourPort}'

data = {}
fingerTable = {
    'me': (ourIP, ourPort),
    'next': '',
    'prev': '',
    '1': '',
    '2': '',
    '3': '',
    '4': '',
    '5': '',
}

# hashedKey = hashlib.sha224(key.encode()).hexdigest()
# int(hasedKey, base=16) <- gets the int version of the digest
# <clientIP>:<clientPort>
clientID = input('Client ID: ')
if clientID != '':
    peerPos = hashlib.sha224(clientID.encode()).hexdigest()
    known_peers = [(clientID, int(peerPos, base=16))]
    clientIP, clientPort = clientID.split(':')
    # clientSock = socket(AF_INET, SOCK_STREAM)
    # clientSock.connect( (clientIP, int(clientPort)) )
    print(f'{ourID=}')
    print(f'{known_peers[0]=}')
else:
    known_peers = []

# Listening Socket
listener = socket(AF_INET, SOCK_STREAM)
listener.setsocket(SOL_SOCKET, SO_REUSEADDR, 1)
listener.bind(('', ourPort))
listener.listen(32)

running = True
while running:
    try:
        threading.Thread(target=handle_client,
                         args=(listener.accept(),),
                         daemon=True).start()
    except KeyboardInterrupt:
        running = False
