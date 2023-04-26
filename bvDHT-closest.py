def updatePeerList():
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
    listy = fingerTable.items()
    end = listy[0]
    for peer in listy:
        if peer[1] < hashedKey and peer[1] > end[1]:
            end = peer
    if end == listy[0]:
        if listy[0][1] > hashedKey:
            end = listy[-1]
    sockRecv.send (str(end[2]) + ":" + (str(end[3]))  + "\n" )


