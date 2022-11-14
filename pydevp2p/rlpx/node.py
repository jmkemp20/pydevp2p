
from pydevp2p.rlpx.capabilities import RLPxCapabilityMsg
from pydevp2p.rlpx.handshake import HandshakeState, Secrets, read_handshake_msg
from pydevp2p.rlpx.rlpx import FrameHeader, SessionState
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4, RLPxP2PMsg, RLPxCapabilityMsg
from pydevp2p.crypto.secp256k1 import privtopub

"""
This maintains all of the information related to an Eth Node along with 
peer connections and their related information.
 - Each Node is pre-added, with each of their private keys, ip-addr, etc.
 - Each peer connection is added upon a proper discovery of that node
    - Utilizing discv4 and discv5
    
This contains the full fledged handler of all information incomming and outgoing 
from the node.
 - There will be a bridge of single functions that can interface with this library

NOTE:
I will wait and see if this is a viable way to track nodes and their peer connections
 - It seems this can be extremely useful if done right, handling all the state
 information in the background, with a simple (push, pull) data bridge

NOTE: 
Why this may be important - In a peer-to-peer network, each node will communicate with
 amongst other nodes, with individual handshake states between each of them, graph theory?

Could be a ton of extra overhead and a lot of unneeded processing
"""

class PeerConnection:
    """
    An RLPx network connection to an <other> node
    
    Before sending messages, a handshake must be performed
    """
    def __init__(self, parentNode: "Node", otherNode: "Node", initiator: bool) -> None:
        self.parentNode = parentNode
        self.otherNode = otherNode
        self.hshakeCompleted = False
        self.handshakeState = HandshakeState(initiator, otherNode.pubK)
        self.sessionState: SessionState | None = None
        self.authInitData = None
        self.authRespData = None
        self.secrets: Secrets | None = None
        if not initiator:
            # need to make sure there is a peer connection for the other node
            otherNode.addConnection(parentNode, True)
            
    def __str__(self) -> str:
        return f"PeerConnection: {self.parentNode.ipaddr} → {self.otherNode.ipaddr}\n {self.handshakeState}\n {self.secrets}"
        
    def handleAuthMsg(self, msg: AuthMsgV4, privK: bytes) -> bytes | None:
        # Here we need to set the RandomPrivKey to the other side of the connection
        otherHandshakeState = self.otherNode.peers.get(self.parentNode.ipaddr).handshakeState
        otherHandshakeState.initNonce = msg.Nonce
        if hasattr(msg, "RandomPrivKey"):
            otherHandshakeState.randomPrivk = msg.RandomPrivKey
        return self.handshakeState.handleAuthMsg(msg, privK)
        
    def handleAuthResp(self, msg: AuthRespV4) -> bytes | None:
        # Here we need to set the RandomPrivKey to the other side of the connection
        otherNodePeer = self.otherNode.peers.get(self.parentNode.ipaddr)
        if otherNodePeer is not None:
            otherHandshakeState = self.otherNode.peers.get(self.parentNode.ipaddr).handshakeState
            otherHandshakeState.respNonce = msg.Nonce
            if hasattr(msg, "RandomPrivKey"):
                otherHandshakeState.randomPrivk = msg.RandomPrivKey
        return self.handshakeState.handleAuthResp(msg)
    
    def getSecrets(self) -> Secrets | None:
        self.secrets = self.handshakeState.secrets(self.authInitData, self.authRespData)
        if self.sessionState is not None:
            print("PeerConnection getSecrets(): Err can't handshake twice")
            return None
        self.sessionState = SessionState(self.secrets)
        return self.secrets
    
    def readFrame(self, data: bytes) -> tuple[FrameHeader, RLPxP2PMsg | RLPxCapabilityMsg | None] | None:
        if not self.sessionState:
            print("PeerConnection readFrame(data): Err sessionState has not been established")
            return None
        
        frameHeader, frameBody = self.sessionState.readFrame(data)
        if frameHeader is None:
            print("PeerConnection readFrame(data): Err Unable to Read Frame Header")
            return None
        elif frameBody is None:
            print("PeerConnection readFrame(data): Err Unable to Read Frame Body")
            return frameHeader, None
        
        return frameHeader, frameBody
            
        
class Node:
    """
    An RLPx and/or Ethereum Node containing the private key and
    other peer connections
    
    Serves as a way to quickly look up a private key based on incomming ip
    """
    def __init__(self, ipaddr: str, privK: bytes) -> None:
        self.ipaddr = ipaddr
        # TODO allow a node without a privk (this is to prevent hardcoding)
        self.privK = privK
        self.pubK = privtopub(privK)
        self.peers: dict[str, PeerConnection] = {} # Dictionary of PeerConnections
        
    def addConnection(self, otherNode: "Node", init: bool) -> PeerConnection:
        p = self.peers.get(otherNode.ipaddr)
        if p is not None:
            # print("addConnection(ipaddr, remotePubK) PeerConnection already added")
            return p          
        p = PeerConnection(self, otherNode, init)
        self.peers[otherNode.ipaddr] = p
        return self.peers[otherNode.ipaddr]
        
    def dropConnection(self, ipaddr: str):
        self.peers.pop(ipaddr)
        
    def readHandshakeMsg(self, msg: bytes | str, srcNode: "Node") -> AuthMsgV4 | AuthRespV4 | None:
        # basically readMsg
        # super weird because this is from the destination or the recievers perspective
        # so if the receiver src.dst is getting an AuthResp then they are definitely the initiator
        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = bytes.fromhex(msg)
        dec, data = read_handshake_msg(self.privK, cleansed) # AuthMsgV4 | AuthRespV4 | None
        
        # Next, check to see if it is auth init or auth resp
        if isinstance(dec, AuthMsgV4):
            peer = self.addConnection(srcNode, init=False)
            # Set the raw authInitData (to be used with secrets)
            peer.authInitData = data
            peer.otherNode.peers.get(self.ipaddr).authInitData = data
            #
            remoteRandomPubk = peer.handleAuthMsg(dec, self.privK)
            if remoteRandomPubk is None:
                print("Auth Msg Error Remote Random Pubk is None")
            # print(f"AUTH INIT {self.ipaddr} → {fromaddr}: Remote Random Pubk: {bytes_to_hex(remoteRandomPubk)}")
            pass
        elif isinstance(dec, AuthRespV4):
            peer = self.addConnection(srcNode, init=True)
            # Set the raw authRespData (to be used with secrets)
            peer.authRespData = data
            peer.otherNode.peers.get(self.ipaddr).authRespData = data
            #
            remoteRandomPubk = peer.handleAuthResp(dec)
            if remoteRandomPubk is None:
                print("Auth Resp Error Remote Random Pubk is None")
            if peer.authInitData is not None and peer.authRespData is not None:
                peer.getSecrets()
            if peer.otherNode.peers.get(self.ipaddr).authInitData is not None and peer.otherNode.peers.get(self.ipaddr).authRespData is not None:
                peer.otherNode.peers.get(self.ipaddr).getSecrets()
            # print(f"AUTH ACK {self.ipaddr} → {fromaddr}: Remote Random Pubk: {bytes_to_hex(remoteRandomPubk)}")
        else:
            pass
        
        return dec
    
    def readRLPxMsg(self, msg: bytes | str, srcNode: "Node" ) -> tuple[FrameHeader, RLPxP2PMsg | RLPxCapabilityMsg | None] | None:
        peer = self.peers.get(srcNode.ipaddr)
        if peer is None:
            print("Node readRLPxMsg(msg, srcNode) Err Unable to Find Peer Connection")
            return None
        
        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = bytes.fromhex(msg)
            
        frameHeader, frameBody = peer.readFrame(cleansed)
        if frameHeader is None:
            print("Node readRLPxMsg(msg, srcNode): Err Unable to Read Frame Header")
            return None
        elif frameBody is None:
            print("Node readRLPxMsg(msg, srcNode): Err Unable to Read Frame Body")
            return frameHeader, None
        
        return frameHeader, frameBody
            
        

all_nodes: dict[str, Node] = {}
        
    
def add_new_node(ipaddr: str, privk: bytes) -> Node:
    n = all_nodes.get(ipaddr)
    if n is not None:
        print("add_new_node(ipaddr, privk) Node already added")
        return n
    n = Node(ipaddr, privk)
    all_nodes[ipaddr] = n
    return n
    
def remove_node(ipaddr: str) -> None:
    all_nodes.pop(ipaddr)

