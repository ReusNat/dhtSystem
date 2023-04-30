from socket import *
from sys import argv
import threading
import hashlib
import binascii

def getline(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode()


def getLocalIPAddress():
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def updateFingerTable():
    offset = int((2**224)/6)
    currIndex = fingerTable['me'][0]
    for x in range(1, 6):
        intIndex = int(currIndex, base=16) + offset
        if intIndex > (2**224):
            currIndex = hex(intIndex-2**224)[2:]
            currIndex = "0"*(56-len(currIndex)) + currIndex
        else:
            currIndex = hex(intIndex)[2:]
            currIndex = "0"*(56-len(currIndex)) + currIndex
        conn = closestAlgorithim(hashedKey=currIndex)
        ip, port = conn.split(':')
        fingerTable[str(x)] = (currIndex, ip, port)


#inputs the non-encrypted Key.
#returns closest peer's userID without a new line... str(ip) + ":" + str(port)
def closestAlgorithim(key=None, hashedKey=None):
    hashedKeyStr = ''
    if hashedKey is None:
        hashedKey = int(hashlib.sha224(key.encode()).hexdigest(),base = 16)
        hashedKeyStr = hashlib.sha224(key.encode()).hexdigest()
    else:
        hashedKeyStr = hashedKey
        hashedKey = int(hashedKey, base=16)
    listy = list(fingerTable.items())
    end = listy[0]
    for peer in listy:
        if peer[1][0] == "-1":
            continue
        if (int(peer[1][0],base=16) < hashedKey\
                and int(peer[1][0],base = 16) > int(end[1][0],base = 16))\
                or end[1][0] == "-1":
            end = peer
    if end == listy[1]:
        if int(listy[0][1][0],base = 16) > hashedKey:
            end = listy[-1]
    connTuple = (end[1][1], int(end[1][2]))
    val = str(end[1][1]) + ":" + str(end[1][2])
    while True:
        if connTuple[0] == fingerTable['me'][1]:
            return val
        clientSock = socket(AF_INET, SOCK_STREAM)
        clientSock.connect(connTuple)
        val = closestPeerSend(hashedKeyStr, clientSock)
        splitVal = val.split(":")
        if (splitVal[0], int(splitVal[1])) == connTuple:
            break
        connTuple = (splitVal[0], int(splitVal[1]))
    return val

# so this works basically by looking through all of our knownPeers list, which
# should include us.
# for each peer in our known peers
# check if that peer's ID is less than the hashedKey and greater than the last
# closest id.
# if thats the case, change the last closest id to the current
# otherwise continue
# now if at the end the closest peer is the first, we check if it's actually
# larger than the ID. If it is, than we know the previous person is actually
# the holder of that ID
# thus, we loop back around to the last peer in our list and return that
# peer's USERID


def closestPeerSend(hashedPos, sock):
    sock.send('CLOSEST_PEER'.encode())
    sock.send(hashedPos.encode())
    return getline(sock)


def closestPeerRecv(connInfo):
    sockRecv = connInfo[0]
    hashedKeyStr = sockRecv.recv(56).decode()
    hashedKey = int(hashedKeyStr,base = 16)
    listy = list(fingerTable.items())
    end = listy[0]
    for peer in listy:
        if peer[1][0] == "-1":
            continue
        if (int(peer[1][0],base = 16) < hashedKey\
                and int(peer[1][0],base=16) > int(end[1][0],base = 16))\
                or end[1][0] == "-1":
            end = peer
    if end == listy[0]:
        if int(listy[0][1][0],base = 16) > hashedKey:
            end = listy[-1]
    sockRecv.send((str(end[1][1]) + ":" + (str(end[1][2]))  + "\n").encode())


def joinSend(hashedPos, sock):
    sock.send('JOIN_DHT_NOW'.encode())
    sock.send((ourID + '\n').encode())
    nextIP, nextPort = getline(sock).split(':')
    nextPos = hashlib.sha224(f'{nextIP}:{nextPort}'.encode()).hexdigest()
    fingerTable['next'] = (nextPos, nextIP, int(nextPort))
    numFilesStr = getline(sock).rstrip()
    
    if numFilesStr == '':
        numFiles = 0
    else:
        numFiles = int(numFilesStr)

    for i in range(0, int(numFiles)):
        fileHashPos = getline(sock)
        fileSize = int(getline(sock).rstrip())
        fileBytes = sock.recv(fileSize)
        data[fileHashPos] = fileBytes

    updatePeerSend((nextIP, int(nextPort)))
    sock.send('OK'.encode())


def joinRecv(connInfo):
    sock = connInfo[0]
    clientUID = getline(sock)
    hashedPos = hashlib.sha224(clientUID.encode()).hexdigest()
    sock.send((closestAlgorithim(key=clientUID) + '\n').encode())
    clientIp, clientPort = clientUID.split(':')

    filesToSend = {}
    for file in data:
        if int(file, base=16) > int(hashedPos, base=16):
            filesToSend[file] = data[file]

    numFiles = (str(len(filesToSend)) + '\n')
    sock.send(numFiles.encode())
    for file in filesToSend:
        sock.send((str(len(filesToSend[file])) + '\n').encode())
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
    if conform == 'OK':
        return
    elif conform == 'FU':
        while conform != 'OK':
            for hashPos in data:
                sock.send(hashPos)
                sock.send(len(data[hashPos]))
                sock.send(data[hashPos])
            conform = sock.recv(2).decode()


def leaveRecv(connInfo):
    pass


def updatePeerSend(peerInfo):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((peerInfo[0], peerInfo[1]))
    sock.send('UPDATE_PEER_'.encode())
    sock.send((ourID + '\n').encode())
    if sock.recv(2).decode() != 'OK':
        while sock.recv(2).decode() != 'OK':
            sock.send((ourID + '\n').encode())


def updatePeerRecv(connInfo):
    sock = connInfo[0]
    prevID = getline(sock).rstrip()
    prevIP, prevPort = prevID.split(':')
    prevHash = hashlib.sha224(prevID.encode()).hexdigest()
    fingerTable['prev'] = (prevHash, prevIP, int(prevPort))
    sock.send('OK'.encode())


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
    sock = connInfo[0]
    hashval = sock.recv(56).decode()
    ourPos = fingerTable['me'][0]
    nextPos = fingerTable['next'][0]
    ourPos = int(ourPos, base=16)
    nextPos = int(nextPos, base=16)
    hashint = int(hashval, base=16)
    if ourPos < nextPos:
        if ourPos < hashint < nextPos:
            sock.send("OK".encode())
            if hashval in data:
                sock.send("OK".encode())
            else:
                sock.send('FU'.encode())
        else:
            sock.send('FU'.encode())
    else:
        if hashint < nextPos and hashint > ourPos:
            sock.send("OK".encode())
            if hashval in data:
                sock.send("OK".encode())
            else:
                sock.send('FU'.encode())
        else:
            sock.send('FU'.encode())


def getDataSend(hashPos, sock):
    sock.send('GET_DATA_NOW'.encode())
    sock.send(hashPos.encode())
    confirm = sock.recv(2)
    if confirm == 'FU':
        return None
    confirm = sock.recv(2)
    if confirm == 'FU':
        return None

    numBytes = getline(sock)
    return sock.recv(int(numBytes.rstrip()))


def getDataRecv(connInfo):
    sock = connInfo[0]
    hashval = sock.recv(56).decode()
    ourPos = fingerTable['me'][0]
    nextPos = fingerTable['next'][0]
    ourPos = int(ourPos, base=16)
    nextPos = int(nextPos, base=16)
    hashint = int(hashval, base=16)
    if ourPos < nextPos:
        if ourPos < hashint < nextPos:
            sock.send("OK".encode())
            if hashval in data:
                sock.send("OK".encode())
                sock.send((str(len(data[hashval]))+'\n').encode())
                sock.send(data[hashval])
            else:
                sock.send('FU'.encode())
        else:
            sock.send('FU'.encode())
    else:
        if hashint < nextPos and hashint > ourPos:
            sock.send("OK".encode())
            if hashval in data:
                sock.send("OK".encode())
                sock.send((str(len(data[hashval]))+'\n').encode())
                sock.send(data[hashval])
            else:
                sock.send('FU'.encode())
        else:
            sock.send('FU'.encode())


def insertSend(hashPos, sock, fileBytes):
    sock.send('INSERT_FILE!'.encode())
    sock.send(hashPos.encode())
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
    hashPos = sock.recv(56).decode()
    if closestAlgorithim(hashedKey=hashPos) == ourID:
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
                closestIP, closestPort = closestAlgorithim(hashedKey=fileHashPos).split(':')
                closestPort = int(closestPort)
                peerSock = socket(AF_INET, SOCK_STREAM)
                peerSock.connect((closestIP, closestPort))
                try:
                    fileBytes = open(fileName, 'rb').read()
                    print(fileBytes[:10])
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
                closestIP, closestPort = closestAlgorithim(hashedKey=fileHashPos).split(':')
                closestPort = int(closestPort)
                peerSock = socket(AF_INET, SOCK_STREAM)
                peerSock.connect((closestIP, closestPort))
                deleteSend(fileHashPos, peerSock)
            elif command == 'get':
                fileName = input('Filename: ')
                closestIP, closestPort = closestAlgorithim(hashedKey=fileHashPos).split(':')
                closestPort = int(closestPort)
                peerSock = socket(AF_INET, SOCK_STREAM)
                peerSock.connect((closestIP, closestPort))
                fileHash = hashlib.sha224(fileName.encode()).hexdigest()
                open(fileName, 'wb').write(getDataSend(fileHash, peerSock))
            elif command == 'leave':
                pass
        except KeyboardInterrupt:
            running = False


clientID = ''
if len(argv) > 2:
    print('Too many arguments\nUsage:\npython3 bvDHT.py <IP>:<Port>\
            \nOR\npython3 bvDHT.py')
    exit(1)
elif len(argv) == 2:
    if ':' not in argv[1]:
        print('Usage:\npython3 bvDHT.py <IP>:<Port>\nOR\npython3 bvDHT.py')
        exit(1)
    else:
        clientID = argv[1]



ourIP = getLocalIPAddress()
ourPort = 5555 
ourID = f'{ourIP}:{ourPort}'
hashedPos = hashlib.sha224(ourID.encode()).hexdigest()
data = {}
fingerTable = {
    'me': ("-1", ourIP, ourPort),
    'intro': (hashedPos, ourIP, ourPort),
    'next': ("-1", ourIP, ourPort),
    'prev': ("-1", ourIP, ourPort),
    '1': ("-1", ourIP, ourPort),
    '2': ("-1", ourIP, ourPort),
    '3': ("-1", ourIP, ourPort),
    '4': ("-1", ourIP, ourPort),
    '5': ("-1", ourIP, ourPort),
}
# hashedKey = hashlib.sha224(key.encode()).hexdigest()
# int(hasedKey, base=16) <- gets the int version of the digest
# <clientIP>:<clientPort>


if clientID != '':
    clientIP, clientPort = clientID.split(':')
    clientHash = hashlib.sha224(clientID.encode()).hexdigest()
    fingerTable['intro'] = (clientHash, clientIP, clientPort)
    closestIP, closestPort = closestAlgorithim(hashedKey=hashedPos).split(':')
    closestPort = int(closestPort)
    closestHash = hashlib.sha224(
            f'{closestIP}:{closestPort}'.encode()).hexdigest()
    fingerTable['prev'] = (closestHash, closestIP, closestPort)
    peerSock = socket(AF_INET, SOCK_STREAM)
    peerSock.connect((closestIP, closestPort))
    joinSend(hashedPos, peerSock)
    fingerTable['me'] = (hashedPos, ourIP, ourPort)
    updateFingerTable()

updateFingerTable()
if fingerTable["next"][0] == "-1":
    fingerTable['next'] = (hashedPos, ourIP, ourPort)
    fingerTable['prev'] = (hashedPos, ourIP, ourPort)


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
