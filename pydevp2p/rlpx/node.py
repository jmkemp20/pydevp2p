
from pydevp2p.rlpx.rlpx import parse_auth_type, read_handshake_msg
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4, PeerConnection
from pydevp2p.crypto.secp256k1 import privtopub
from pydevp2p.rlpx.types import PeerConnection

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

# TODO MAKE THIS MORE LIKE A GRAPH AND LESS LIKES A MANY TO MANY DICTIONARY

class Node:
    """
    An RLPx and/or Ethereum Node containing the private key and
    other peer connections
    
    Serves as a way to quickly look up a private key based on incomming ip
    """
    def __init__(self, ipaddr: str, privK: bytes) -> None:
        self.ipaddr = ipaddr
        self.privK = privK
        self.pubK = privtopub(privK)
        self.laddr = ipaddr # TODO need to convert to logical addr
        self.peers: dict[str, PeerConnection] = {} # Dictionary of PeerConnections
        
    def addConnection(self, ipaddr: str, remotePubK: bytes) -> PeerConnection:
        p = self.peers.get(ipaddr)
        if p is not None:
            print("addConnection(ipaddr, remotePubK) PeerConnection already added")
            return p          
        p = PeerConnection(self.privK, remotePubK, False, ipaddr)
        self.peers[ipaddr] = p
        return p
        
    def dropConnection(self, ipaddr: str):
        self.peers.pop(ipaddr)
        
    def readHandshakeMsg(self, msg: bytes | str) -> AuthMsgV4 | AuthRespV4 | None:
        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = bytes.fromhex(msg)
        dec = read_handshake_msg(self.privK, cleansed)
        return dec
        

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

