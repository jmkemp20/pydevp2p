from pydevp2p.discover.v4wire.decode import decodeDiscv4
from pydevp2p.discover.v5wire.encoding import Discv5Codec, Header
from pydevp2p.discover.v5wire.msg import Packet
from pydevp2p.elliptic.utils import pubk_to_idv4
from pydevp2p.rlpx.capabilities import RLPxCapabilityMsg
from pydevp2p.rlpx.handshake import HandshakeState, Secrets, read_handshake_msg
from pydevp2p.rlpx.rlpx import FrameHeader, SessionState
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4, RLPxP2PMsg, RLPxCapabilityMsg, RLPxTempMsg
from pydevp2p.crypto.secp256k1 import privtopub
from pydevp2p.utils import bytes_to_int, framectx, hex_to_bytes

"""
This maintains all of the information related to an Eth Node along with 
peer connections and their related information.
 - Each Node is pre-added, with each of their private keys, ip-addr, etc.
 - Each peer connection is added upon a proper discovery of that node
    - Utilizing discv4 and discv5
    
This contains the full fledged handler of all information incomming and outgoing 
from the node.
 - There will be a bridge of single functions that can interface with this library
"""


class PeerConnection:
    """
    An RLPx network connection to an <other> node

    Before sending messages, a handshake must be performed
    """

    def __init__(self, parentNode: "Node", otherNode: "Node") -> None:
        self.parentNode = parentNode
        self.otherNode = otherNode
        # RLPx related fields
        self.handshakeState: HandshakeState | None = None
        self.sessionState: SessionState | None = None
        self.authInitData = None
        self.authRespData = None
        self.secrets: Secrets | None = None

    def __str__(self) -> str:
        return f"PeerConnection: {self.parentNode.ipaddr} → {self.otherNode.ipaddr}\n {self.handshakeState}\n {self.secrets}"

    def initHandshake(self, initiator: bool) -> HandshakeState:
        # Called upon an Auth Msg or Auth Ack Msg to setup State
        self.handshakeState = HandshakeState(initiator, self.otherNode.pubK)
        return self.handshakeState

    def handleAuthMsg(self, msg: AuthMsgV4, privK: bytes) -> bytes | None:
        # Here we need to set the RandomPrivKey to the other side of the connection
        otherNodePeer = self.otherNode.peers.get(self.parentNode.ipaddr)
        # Make sure the other nodes PeerConnection to the parent node Handshake State is initialized
        if otherNodePeer.handshakeState is None:
            otherNodePeer.initHandshake(True)
        otherHandshakeState = self.otherNode.peers.get(
            self.parentNode.ipaddr).handshakeState
        otherHandshakeState.initNonce = msg.Nonce
        if hasattr(msg, "RandomPrivKey"):
            otherHandshakeState.randomPrivk = msg.RandomPrivKey
        return self.handshakeState.handleAuthMsg(msg, privK)

    def handleAuthResp(self, msg: AuthRespV4) -> bytes | None:
        # Here we need to set the RandomPrivKey to the other side of the connection
        otherNodePeer = self.otherNode.peers.get(self.parentNode.ipaddr)
        # Make sure the other nodes PeerConnection to the parent node Handshake State is initialized
        if otherNodePeer.handshakeState is None:
            otherNodePeer.initHandshake(False)
        if otherNodePeer is not None:
            otherHandshakeState = self.otherNode.peers.get(
                self.parentNode.ipaddr).handshakeState
            otherHandshakeState.respNonce = msg.Nonce
            if hasattr(msg, "RandomPrivKey"):
                otherHandshakeState.randomPrivk = msg.RandomPrivKey
        return self.handshakeState.handleAuthResp(msg)

    def getSecrets(self) -> Secrets | None:
        self.secrets = self.handshakeState.secrets(
            self.authInitData, self.authRespData)
        # if self.sessionState is not None:
        #     print("PeerConnection getSecrets(): Err can't handshake twice")
        #     return None
        self.sessionState = SessionState(self.secrets)
        return self.secrets

    def readFrame(self, data: bytes) -> tuple[FrameHeader, RLPxP2PMsg | RLPxCapabilityMsg | RLPxTempMsg | None] | None:
        if not self.sessionState:
            print(
                f"{framectx()} PeerConnection readFrame(data): Err sessionState has not been established")
            return None

        frameHeader, frameBody = self.sessionState.readFrame(data)
        if frameHeader is None:
            print(
                f"{framectx()} PeerConnection readFrame(data): Err Unable to Read Frame Header")
            return None
        elif frameBody is None:
            print(
                f"{framectx()} PeerConnection readFrame(data): Err Unable to Read Frame Body")
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
        # Handles enc/dec of discovery v5 and pending/active discovery read writes
        self.discv5 = Discv5Codec(self.privK)
        # List of active RLPx peers (already discovered/authenticated)
        # Dictionary of PeerConnections
        self.peers: dict[str, PeerConnection] = {}

    def addConnection(self, otherNode: "Node") -> PeerConnection:
        p = self.peers.get(otherNode.ipaddr)
        if p is not None:
            # print("addConnection(ipaddr) PeerConnection already added")
            return p
        p = PeerConnection(self, otherNode)
        self.peers[otherNode.ipaddr] = p
        return self.peers[otherNode.ipaddr]

    def dropConnection(self, ipaddr: str):
        self.peers.pop(ipaddr)

    def readDiscv4Msg(self, msg: bytes | str, srcNode: "Node") -> tuple[Header, Packet | None] | None:
        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = bytes.fromhex(msg)

        return decodeDiscv4(cleansed)

    def readDiscv5Msg(self, msg: bytes | str, srcNode: "Node") -> tuple[Header, Packet] | None:
        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = bytes.fromhex(msg)

        header, packet, session = self.discv5.decode(cleansed, srcNode.ipaddr)
        # If the packet for dstNode (self) is WHOAREYOU, must setup the Handshake Session for the
        # .. sender None i.e. srcNode
        if header is not None and packet is not None:
            if bytes_to_int(header.flag) == 1 and packet.kind == 254:
                # WHOAREYOU/v5
                srcNode.discv5.sc.storeSentHandshake(
                    pubk_to_idv4(self.pubK), self.ipaddr, packet)
            elif bytes_to_int(header.flag) == 2:
                srcNode.discv5.sc.storeNewSession(pubk_to_idv4(
                    self.pubK), self.ipaddr, session.keysFlipped())

        return header, packet

    def readHandshakeMsg(self, msg: bytes | str, srcNode: "Node") -> AuthMsgV4 | AuthRespV4 | None:
        # basically readMsg
        # super weird because this is from the destination or the recievers perspective
        # so if the receiver src.dst is getting an AuthResp then they are definitely the initiator
        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = hex_to_bytes(msg)
        # AuthMsgV4 | AuthRespV4 | None
        dec, data = read_handshake_msg(self.privK, cleansed)

        # Next, check to see if it is auth init or auth resp
        if isinstance(dec, AuthMsgV4):
            peer = self.addConnection(srcNode)
            if peer.handshakeState is None:
                peer.initHandshake(False)
            # Set the peer connection of the sender's node to this node
            if peer.otherNode.peers.get(self.ipaddr) is None:
                peer.otherNode.addConnection(self)
            # Set the raw authInitData (to be used with secrets)
            peer.authInitData = data
            peer.otherNode.peers.get(self.ipaddr).authInitData = data
            #
            remoteRandomPubk = peer.handleAuthMsg(dec, self.privK)
            if remoteRandomPubk is None:
                print(f"{framectx()} Auth Msg Error Remote Random Pubk is None")
            # print(f"AUTH INIT {self.ipaddr} → {fromaddr}: Remote Random Pubk: {bytes_to_hex(remoteRandomPubk)}")
            pass
        elif isinstance(dec, AuthRespV4):
            peer = self.addConnection(srcNode)
            if peer.handshakeState is None:
                peer.initHandshake(True)
            # Set the peer connection of the sender's node to this node
            if peer.otherNode.peers.get(self.ipaddr) is None:
                peer.otherNode.addConnection(self)
            # Set the raw authRespData (to be used with secrets)
            peer.authRespData = data
            peer.otherNode.peers.get(self.ipaddr).authRespData = data
            #
            remoteRandomPubk = peer.handleAuthResp(dec)
            if remoteRandomPubk is None:
                print(f"{framectx()} Auth Resp Error Remote Random Pubk is None")
            if peer.authInitData is not None and peer.authRespData is not None:
                peer.getSecrets()
            if peer.otherNode.peers.get(self.ipaddr).authInitData is not None and peer.otherNode.peers.get(self.ipaddr).authRespData is not None:
                peer.otherNode.peers.get(self.ipaddr).getSecrets()
            # print(f"AUTH ACK {self.ipaddr} → {fromaddr}: Remote Random Pubk: {bytes_to_hex(remoteRandomPubk)}")
        else:
            pass

        return dec

    def readRLPxMsg(self, msg: bytes | str, srcNode: "Node") -> tuple[FrameHeader | None, RLPxP2PMsg | RLPxCapabilityMsg | RLPxTempMsg | None]:
        peer = self.peers.get(srcNode.ipaddr)
        if peer is None:
            print(
                f"{framectx()} Node readRLPxMsg(msg, srcNode) Err Unable to Find Peer Connection")
            return None

        cleansed = msg
        if isinstance(cleansed, str):
            cleansed = bytes.fromhex(msg)

        frameHeader, frameBody = peer.readFrame(cleansed)
        if frameHeader is None:
            print(
                f"{framectx()} Node readRLPxMsg(msg, srcNode): Err Unable to Read Frame Header")
            return None, None
        elif frameBody is None:
            print(
                f"{framectx()} Node readRLPxMsg(msg, srcNode): Err Unable to Read Frame Body")
            return frameHeader, None

        return frameHeader, frameBody
