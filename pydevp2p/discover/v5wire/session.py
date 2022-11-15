
# geth/p2p/discover/v5wire/session.go

class SessionID:
    """
    SessionID identifies a session or handshake.
    """
    id: bytes
    addr: str
    
class Session:
    """
    Session contains session information
    """
    writeKey: bytes
    readKey: bytes
    nonceCounter: int
    def __init__(self) -> None:
        pass
    
    def __str__(self) -> str:
        pass
    
    def keysFlipped(self) -> "Session":
        pass

class SessionCache:
    """
    The SessionCache keeps negotiated encryption keys and state for in-progress
    handshakes in the Discovery v5 wire protocol.
    """
    sessions = {}
    handshakes = {}
    def __init__(self) -> None:
        pass
    
    def __str__(self) -> str:
        pass
    
    def nextNonce(self, s: Session) -> bytes: # len bytes 32
        # nextNonce creates a nonce for encrypting a message to the given session.
        pass
    
    def session(self, enode_id: bytes, addr: str) -> Session:
        # session returns the current session for the given node, if any.
        pass
    
    def readKey(self, enode_id: bytes, addr: str) -> bytes:
        # readKey returns the current read key for the given node.
        pass
    
    def storeNewSession(self, enode_id: bytes, addr: str, s: Session):
        # storeNewSession stores new encryption keys in the cache.
        pass
    
    # def getHandshake(self, enode_id: bytes, addr: str, s: Session) -> Whoareyou:
    #     # getHandshake gets the handshake challenge we previously sent to the given remote node.
    #     pass
    
    # def storeSentHandshake(self, enode_id: bytes, addr: str, challenge: Whoareyou):
    #     # storeSentHandshake stores the handshake challenge sent to the given remote node.
    #     pass
    
    def deleteHandshake(self, enode_id: bytes, addr: str):
        # deleteHandshake deletes handshake data for the given node.
        pass
    
    def handshakeGC(self):
        # handshakeGC deletes timed-out handshakes.
        pass
    
    def generateNonce(self, counter: int) -> bytes: # len bytes 32
        pass
    
    def generateMaskingIV(self) -> bytes:
        pass
    
