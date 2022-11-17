
# geth/p2p/discover/v5wire/session.go

from pydevp2p.discover.v5wire.msg import Whoareyou


class SessionID:
    """
    SessionID identifies a session or handshake.
    """
    def __init__(self, enodeID: bytes, addr: str) -> None:
        self.enodeID = enodeID # 32 bytes Pubk unique id of node
        self.addr = addr # String IP address
    
class Session:
    """
    Session contains session information
    """
    def __init__(self, writeKey: bytes, readKey: bytes, nonceCounter: int) -> None:
        self.writeKey = writeKey
        self.readKey = readKey
        self.nonceCounter = nonceCounter
    
    def __str__(self) -> str:
        pass
    
    def keysFlipped(self) -> "Session":
        pass

class SessionCache:
    """
    The SessionCache keeps negotiated encryption keys and state for in-progress
    handshakes in the Discovery v5 wire protocol.
    """
    def __init__(self) -> None:
        self.sessions: dict[SessionID, Session] = {}
        self.handshakes: dict[SessionID, Whoareyou] = {}
    
    def __str__(self) -> str:
        pass
    
    def nextNonce(self, s: Session) -> bytes: # len bytes 32
        # nextNonce creates a nonce for encrypting a message to the given session.
        s.nonceCounter += 1
        return self.generateNonce(s.nonceCounter)
    
    def session(self, enodeID: bytes, addr: str) -> Session | None:
        # session returns the current session for the given node, if any.
        return self.sessions.get(SessionID(enodeID, addr))
    
    def readKey(self, enodeID: bytes, addr: str) -> bytes | None:
        # readKey returns the current read key for the given node.
        s = self.session(enodeID, addr)
        if s is not None:
            return s.readKey
        return None
    
    def storeNewSession(self, enodeID: bytes, addr: str, s: Session) -> Session:
        # storeNewSession stores new encryption keys in the cache.
        self.sessions[SessionID(enodeID, addr)] = s
        return s
    
    def getHandshake(self, enodeID: bytes, addr: str, s: Session) -> Whoareyou | None:
        # getHandshake gets the handshake challenge we previously sent to the given remote node.
        return self.handshakes.get(SessionID(enodeID, addr))
    
    def storeSentHandshake(self, enodeID: bytes, addr: str, challenge: Whoareyou):
        # storeSentHandshake stores the handshake challenge sent to the given remote node.
        # TODO Might need to add: challenge.sent = sc.clock.Now()
        self.handshakes[SessionID(enodeID, addr)] = challenge
    
    def deleteHandshake(self, enodeID: bytes, addr: str) -> Whoareyou | None:
        # deleteHandshake deletes handshake data for the given node.
        # .. returns Whoareyou if successfully deleted otherwise None if err
        return self.handshakes.pop(SessionID(enodeID, addr))
    
    def handshakeGC(self):
        # handshakeGC deletes timed-out handshakes.
        # TODO Iterate over handshakes in self.handshakes and delete time-out keys
        pass
    
    def generateNonce(self, counter: int) -> bytes: # len bytes 32
        nonce = b''
        # put counter into n[:4]
        # random bytes read into n[4:32]
        return nonce
    
    def generateMaskingIV(self, len: int) -> bytes:
        # TODO returns random bytes of len
        pass
    
