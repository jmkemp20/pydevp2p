from Crypto.Hash import SHA256
from Crypto.Util import Counter 
from Crypto.Cipher import AES

from pydevp2p.crypto.secp256k1 import privtopub
from pydevp2p.discover.datatypes import Enode
from pydevp2p.discover.v5wire.msg import Packet, Whoareyou
from pydevp2p.discover.v5wire.session import Session, SessionCache
from pydevp2p.utils import bytes_to_hex, bytes_to_int
# geth/p2p/discover/v5wire/encoding.go

# Packet header flag values
flagMessage = 0
flagWhoareyou = 1
flagHandshake = 2

# Protocol Constants
version = 1
minVersion = 1
sizeofMaskingIV = 16
# The minimum size of any Discovery v5 packet is 63 bytes.
# Should reject packets smaller than minPacketSize.
minPacketSize = 63
# This refers to the data after the static headers
minMessageSize = 48
randomPacketMsgSize = 20
protocolID = b'd' + b'i' + b's' + b'c' + b'v' + b'5'


class StaticHeader:
    SIZE = 6 + 2 + 1 + 12 + 2
    def __init__(self, rawData: bytes) -> None:
        self.protocolID = rawData[:6] # 6 bytes
        self.version = bytes_to_int(rawData[6:8]) # uint16
        self.flag = bytes_to_int(rawData[8:9]) # 1 bytes (0, 1, 2)
        self.nonce = rawData[9:21]  # 12 bytes
        self.authSize = bytes_to_int(rawData[21:23]) # uint16
    
    def checkValid(self, packetLen: int) -> bool:
        """checkValid performs some basic validity checks on the header.
        The packetLen here is the length remaining after the static header.

        Args:
            packetLen (int): The total packet length

        Returns:
            bool: Whether or not the static header is valid
        """
        if self.protocolID != protocolID:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Protocol ID, Expected {protocolID} Got {self.protocolID}")
            return False
        if self.version < minVersion:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Protocol Version, Expected {minVersion} Got {self.version}")
            return False
        if self.flag != flagWhoareyou and packetLen < minMessageSize:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Msg Len, Expected {packetLen} < {minMessageSize}")
            return False
        if self.authSize > packetLen:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Auth Len, Expected {packetLen} < {self.authSize}")
            return False
        return True

class Header:
    def __init__(self, IV: bytes, staticHeader: StaticHeader = None, authData: bytes = None, srcEnodeID: bytes = None) -> None:
        self.IV = IV # sizeofMaskingIV ( 16 bytes )
        self.staticHeader = staticHeader
        self.authData = authData
        self.src = srcEnodeID # enode.ID 32 bytes pubk of src
    
    def mask(self, destID: bytes):
        mask_key = destID[:16]
        ctr = Counter.new(len(mask_key) * 8, initial_value=bytes_to_int(self.IV))
        return AES.new(mask_key, AES.MODE_CTR, counter=ctr)
    
class WhoareyouAuthData:
    SIZE = 16 + 8
    def __init__(self, idNonce: bytes, recordSeq: bytes) -> None:
        self.idNonce = idNonce # 16 bytes - ID proof data
        self.recordSeq = recordSeq # uint64 (8 bytes) - Highest known ENR sequence of requester

class HandshakeAuthData:
    SIZE = 32 + 1 + 1 # Only h or { srcID, sigSize, pubkSize }
    def __init__(self, srcEnodeId: bytes, sigSize: int, pubkSize: int, sig: bytes, pubk: bytes, record: bytes) -> None:
        self.srcEnodeId = srcEnodeId # 32 bytes pubk
        self.sigSize = sigSize # uint8 byte 8 bits
        self.pubkSize = pubkSize # uint8 byte 8 bits
        # Trailing variable-size data.
        self.sig = sig
        self.pubk = pubk
        self.record = record

class MessageAuthData:
    SIZE = 32
    def __init__(self, srcEnodeId: bytes) -> None:
        self.srcEnodeId = srcEnodeId # 32 bytes pubk
        
sizeofStaticPacketData = sizeofMaskingIV + StaticHeader.SIZE

class Discv5Codec:
    """
    Codec encodes and decodes Discovery v5 packets.
    This type is not safe for concurrent use.
    """
    sha256 = SHA256
    privk: bytes = None
    pubk: bytes = None    
    sc: SessionCache = None 
    
    # encoder buffers
    buf: bytes = None # whole packet
    headbuf: bytes = None # packet header
    msgbuf: bytes = None # message RLP plaintext
    msgctbuf: bytes = None # message data ciphertext
    
    # decoder buffers
    reader: bytes = None
    
    def __init__(self, privk: bytes) -> None:
        self.sha256 = SHA256.new()
        self.privk = privk
        self.pubk = privtopub(privk)
        self.sc = SessionCache()
        return
    
    def __str__(self) -> str:
        return ""
    
    ########## DECODERS ##########
    
    def decode(self, input: bytes, fromAddr: str) -> tuple[bytes, Enode, Packet] | None:
        """Decode decodes a discovery v5 packet.

        Args:
            input (bytes): The raw data to decode, unmask, etc
            fromAddr (str): The address of who sent the discovery v5 packet

        Returns:
            tuple[bytes, Enode, Packet] | None: (srcPubk, Enode, Packet) or None if err occurs
        """
        if len(input) < minPacketSize:
            print(f"Discv5Codec decode(input, fromAddr) Err Invalid Packet Len, Expected >= {minPacketSize} Got {len(input)}")
            return None
        
        # Unmask the static header.
        head = Header(input[:sizeofMaskingIV])
        mask = head.mask(self.pubk)
        staticHeader_masked = input[sizeofMaskingIV: sizeofStaticPacketData]
        staticHeader_unmasked = mask.decrypt(staticHeader_masked)
        
        # Decode and verify the static header.
        head.staticHeader = StaticHeader(staticHeader_unmasked)
        print("flag:", head.staticHeader.flag)
        remainingInput = len(input) - sizeofStaticPacketData
        if not head.staticHeader.checkValid(remainingInput):
            print("Discv5Codec decode(input, fromAddr) Err Static Header Invalid")
            return None
        
        # Unmask auth data
        authDataEnd = sizeofStaticPacketData + head.staticHeader.authSize
        authData_masked = input[sizeofStaticPacketData:authDataEnd]
        authData_unmasked = mask.decrypt(authData_masked)
        head.authData = authData_unmasked
        
        # TODO Delete timed-out handshakes. This must happen before decoding to 
        # .. avoid processing the same handshake twice
        # self.sc.handshakeGC()
        
        # Decode auth part and message.
        headerData = input[:authDataEnd]
        msgData = input[authDataEnd:]
        msgFlag = head.staticHeader.flag
        if msgFlag == flagWhoareyou:
            p = self.decodeWhoareyou(head, headerData)
        elif msgFlag == flagHandshake:
            dec_handshake_msg = self.decodeHandshakeMessage(fromAddr, head, headerData, msgData)
            if dec_handshake_msg is not None:
                n, p = dec_handshake_msg
        elif msgFlag == flagMessage:
            p = self.decodeMessage(fromAddr, head, headerData, msgData)
        else:
            print(f"Discv5Codec decode(input, fromAddr) Err Invalid Msg Flag, Expected (0, 1, 2) Got {msgFlag}")
            return None
        
        return
    
    def decodeWhoareyou(self, head: Header, headerData: bytes) -> Packet | None:
        """decodeWhoareyou reads packet data after the header as a WHOAREYOU packet.

        Args:
            head (Header): The Header of the packet
            headerData (bytes): The raw Header Data

        Returns:
            Packet | None: Generic Packet or None if err occurs
        """
        return
    
    def decodeHandshakeMessage(self, fromAddr: str, head: Header, headerData: bytes, msgData: bytes) -> tuple[Enode, Packet] | None:
        """Decodes a discovery v5 handshake message data returning the src enode ID (pubk) and ENRRecord
        along with the decoded Packet

        Args:
            fromAddr (str): The ip address of the sender of this packet
            head (Header): The Header of this packet
            headerData (bytes): The raw packet header data 
            msgData (bytes): The raw packet msg data 

        Returns:
            tuple[Enode, Packet] | None: (Enode - of src, Packet - decoded msg) or None if err occurs
        """
        return
    
    def decodeHandshake(self, fromAddr: str, head: Header) -> tuple[Enode, HandshakeAuthData, Session] | None:
        """Decodes a discovery v5 handshake packet returning the src enode ID (pubk) and ENRRecord
        along with the decoded Packet

        Args:
            fromAddr (str): The ip address of the sender of this packet
            head (Header): The Header of this packet

        Returns:
            tuple[Enode, HandshakeAuthData, Session] | None: (Enode, HandshakeAuthData, Session) or None
        """
        return
    
    def decodeHandshakeAuthData(self, head: Header) -> HandshakeAuthData | None:
        """decodeHandshakeAuthData reads the authdata section of a handshake packet.

        Args:
            head (Header): Header of the handshake packet

        Returns:
            HandshakeAuthData | None: Decoded Handshake Auth Data or None on err
        """
        return
    
    def decodeHandshakeRecord(self, local: Enode, wantID: bytes, remote: bytes) -> Enode | None:
        """decodeHandshakeRecord verifies the node record contained in a handshake packet. The
        remote node should include the record if we don't have one or if ours is older than the
        latest sequence number.

        Args:
            local (Enode): The local enode
            wantID (bytes): The desired pubk to prove verification
            remote (bytes): raw bytes of remote ENR Record

        Returns:
            Enode | None: Returns the enode of src or None if err
        """
        return
    
    def decodeMessage(self, fromAddr: str, head: Header, headerData: bytes, msgData: bytes) -> Packet | None:
        """decodeMessage reads packet data following the header as an ordinary message packet (0).

        Args:
            fromAddr (str): The IP address of who sent this message
            head (Header): The Header information of the packet
            headerData (bytes): The raw header data of the packet
            msgData (bytes): The raw msgData of the packet to decode

        Returns:
            Packet | None: The decoded msg Packet or None if err
        """
        return
    
    def decryptMessage(self, input: bytes, nonce: bytes, headerData: bytes, readKey: bytes) -> Packet | None:
        """Decrypts a message using AES-GCM with the key, nonce, input and headerData

        Args:
            input (bytes): The ciphertext to decrypt
            nonce (bytes): Given Nonce value
            headerData (bytes): The Auth data used
            readKey (bytes): The AES key

        Returns:
            Packet | None: The decrypted Packet or None if err
        """
        return
        
    ########## ENCODERS ##########
    
    def encode(self, enodeID: bytes, addr: str, packet: Packet, challenge: Whoareyou) -> tuple[bytes, bytes] | None:
        # TODO Encode encodes a packet to a node. 'id' and 'addr' specify the destination node. The
        # .. 'challenge' parameter should be the most recently received WHOAREYOU packet from that node
        return
    
    def encodeRaw(self, enodeID: bytes, head: Header, msgdata: bytes) -> bytes:
        # TODO EncodeRaw encodes a packet with the given header.
        return
    
    def writeHeaders(self, head: Header):
        # TODO
        return
    
    def makeHeader(self, toEnodeID: bytes, flag: bytes, authsizeExtra: int) -> Header:
        # TODO makeHeader creates a packet header.
        return 
    
    def encodeRandom(self, toEnodeID: bytes) -> tuple[Header, bytes] | None:
        # TODO encodeRandom encodes a packet with random content.
        return 
    
    def encodeWhoareyou(self, toEnodeID: bytes, packet: Whoareyou) -> Header:
        # TODO encodeWhoareyou encodes a WHOAREYOU packet.
        return 
    
    def encodeHandshakeHeader(self, toEnodeID: bytes, addr: str, challenge: Whoareyou) -> tuple[Header, Session] | None:
        # TODO encodeHandshakeHeader encodes the handshake message packet header.
        return 
    
    def makeHandshakeAuth(self, toEnodeID: bytes, addr: str, challenge: Whoareyou) -> tuple[HandshakeAuthData, Session] | None:
        # TODO makeHandshakeAuth creates the auth header on a request packet following WHOAREYOU.
        return
    
    def encodeMessageHeader(self, toEnodeID: bytes, s: Session) -> Header | None:
        # TODO encodeMessageHeader encodes an encrypted message packet.
        return
    
    def encryptMessage(self, s: Session, p: Packet, head: Header, headerData: bytes) -> bytes | None:
        # TODO encodeMessageHeader encodes an encrypted message packet.
        return
        
