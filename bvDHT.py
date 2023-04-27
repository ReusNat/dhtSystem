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

def updateFingerTable():
    pass


#inputs the non-encrypted Key.
#returns closest peer's userID without a new line... str(ip) + ":" + str(port)
def closestAlgorithim(key):
    hashedKey = hashlib.sha224(key.encode()).hexdigest()
    listy = fingerTable.items()
    end = listy[0]
    for peer in listy:
        if peer[1] < hashedKey and peer[1] > end[1]:
            end = peer
    if end == listy[1]:
        if listy[0][1] > hashedKey:
            end = listy[-1]
    connTuple = (end[2], int(end[3]))
    val = str(end[2]) + ":" + str(end[3])
    while True:
        clientSock = socket(AF_INET, SOCK_STREAM)
        clientSock.connect(connTuple)
        val = closestPeerSend(hashedKey, clientSock)
        splitVal = val.split(":")
        if (splitVal[0], splitVal[1]) == connTuple:
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


def closestPeerSend(hashedPos, connInfo=None):
    if connInfo:
        sock, sockAddress = connInfo
    else:
        sock = socket(AF_INET, SOCK_STREAM)
        cIP, cPort = clientID.split(':')
        sock.connect((cIP, int(cPort)))
    sock.send('CLOSEST_PEER'.encode())
    sock.send(hashedPos)
    return getline(sock)


def closestPeerRecv(connInfo):
    sock = connInfo[0]
    hashedKey = getline(sock)
    listy = fingerTable.items()
    end = listy[0]
    for peer in listy:
        if peer[1] < hashedKey and peer[1] > end[1]:
            end = peer
    if end == listy[0]:
        if listy[0][1] > hashedKey:
            end = listy[-1]
    sockRecv.send(str(end[2]) + ":" + (str(end[3]))  + "\n")


def joinSend(hashedPos, sock):
    sock.send('JOIN_DHT_NOW'.encode())
    sock.send(ourID.encode())
    nextIP, nextPort = getline(sock).split(':')
    nextPos = hashlib.sha224(f'{nextIP}:{nextPort}'.encode()).hexdigest()
    fingerTable['next'] = (nextPos, nextIP, int(nextPort))
    numFiles = getline(sock)

    for i in range(0, numFiles):
        fileHashPos = getline(sock)
        fileSize = int(getline(sock).rstrip())
        fileBytes = sock.recv(fileSize)
        data[fileHashPos] = fileBytes
    updatePeerSend(ourID)
    sock.send('ok'.encode())


def joinRecv(hashedPos, connInfo):
    sock = connInfo[0]
    clientUID = getline(sock)
    hashedPos = hashlib.sha224(clientUID.encode()).hexdigest()
    sock.send((closestAlgorithim(clientUID) + '\n'))
    clientIp, clientPort = clientUID.split(':')

    filesToSend = {}
    for file in data:
        if int(file, base=16) > int(hashedPos, base=16):
            filesToSend[file] = data[file]

    sock.send(str(len(filesToSend)).encode())
    for file in filesToSend:
        sock.send(str(len(filesToSend[file])).encode())
        sock.send(filesToSend[file])

    comfirm = sock.recv(2).decode()
    if comfirm == 'OK':
        fingerTable['next'] = (hashedPos, clientIp, int(clientPort))


def leaveSend(sock):
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


def insertSend(hashPos, sock, fileBytes):
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
    hashPos = int(sock.recv(56).decode(), base=16)
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


def deleteSend(hashPos, sock):
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
    sock = connInfo[0]
    hashPos = sock.recv(56)
    if closestPeerSend(connInfo, hashPos) == fingerTable['me']:
        sock.send('OK'.encode())
        if hashPos in data:
            del data[hashPos]
            sock.send('OK'.encode())
        else:
            sock.send('FU'.encode())
    else:
        sock.send('FU'.encode())


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


def run():
    running = True
    while running:
        try:
            commands = ['insert', 'delete', 'leave', 'get']
            command = input('What do? ').lower()

            if command not in commands:
                print('Improper command,\
                        please use one of the following: ')
                print(commands)
            elif command == 'insert':
                fileName = input('File name: ')
                fileHashPos = hashlib.sha224(
                        fileName.encode()).hexdigest()
                closestIP, closestPort = closestPeerSend(fileHashPos).split(':')
                closestPort = int(closestPort)
                peerSock = socket(AF_INET, SOCK_STREAM)
                peerSock.connect((closestIP, closestPort))
                try:
                    fileBytes = open(fileName, 'rb').read()
                    if insertSend(fileHashPos, peerSock, fileBytes):
                        print(f'{fileName} inserted.')
                    else:
                        print('Insertion failed.')
                except FileNotFoundError:
                    print('File doesn\'t exist.')
            elif command == 'delete':
                fileName = input('File name: ')
                fileHashPos = hashlib.sha224(
                        fileName.encode()).hexdigest()
                closestIP, closestPort = closestPeerSend(fileHashPos).split(':')
                closestPort = int(closestPort)
                peerSock = socket(AF_INET, SOCK_STREAM)
                peerSock.connect((closestIP, closestPort))
                deleteSend(fileHashPos, peerSock)
            elif command == 'get':
                pass
            elif command == 'leave':
                pass
        except KeyboardInterrupt:
            running = False


if len(argv) < 3:
    exit('Not enough arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')
elif len(argv) > 3:
    exit('Too many arguments\nUsage: python3 bvDHT.py <yourIP> <yourPort>')

ourIP = argv[1]
ourPort = argv[2]
ourID = f'{ourIP}:{ourPort}'
hashedKey = hashlib.sha224(ourID.encode()).hexdigest()
data = {}
fingerTable = {
    'me': (hashedKey, ourIP, int(ourPort)),
    'next': (None,None,None),
    'prev': (None,None,None),
    '1': (None,None,None),
    '2': (None,None,None),
    '3': (None,None,None),
    '4': (None,None,None),
    '5': (None,None,None),
}
# hashedKey = hashlib.sha224(key.encode()).hexdigest()
# int(hasedKey, base=16) <- gets the int version of the digest
# <clientIP>:<clientPort>
clientID = input('Client ID: ')
if clientID != '':
    hashedPos = hashlib.sha224(f'{ourIP}:{ourPort}'.encode()).hexdigest()
    closestIP, closestPort = closestAlgorithim(hashedPos).split(':')
    closestPort = int(closestPort)
    closestHash = hashlib.sha224(
            f'{closestIP}:{closestPort}'.encode()).hexdigest()
    fingerTable['prev'] = (closestHash, closestIP, closestPort)
    peerSock = socket(AF_INET, SOCK_STREAM)
    peerSock.connect((closestIP, closestPort))
    joinSend(hashedPos, peerSock)

# Listening Socket
listener = socket(AF_INET, SOCK_STREAM)
listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
listener.bind(('', int(ourPort)))
listener.listen(32)

threading.Thread(target=run,
                 args=(),
                 daemon=True).start()
running = True
while running:
    try:
        threading.Thread(target=handleClient,
                         args=(listener.accept(),),
                         daemon=True).start()
    except KeyboardInterrupt:
        running = False
