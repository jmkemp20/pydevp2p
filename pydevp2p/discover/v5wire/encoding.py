from Crypto.Hash import SHA256
from Crypto.Util import Counter 
from Crypto.Cipher import AES
from rlp.codec import decode

from pydevp2p.crypto.secp256k1 import privtopub
from pydevp2p.discover.datatypes import Enode, Record
from pydevp2p.discover.v5wire.crypto import decodePubk, decryptGCM, deriveKeys, verifyIDSignature
from pydevp2p.discover.v5wire.msg import Packet, Unknown, Whoareyou, decodeMessageByType
from pydevp2p.discover.v5wire.session import Session, SessionCache
from pydevp2p.elliptic.utils import pubk_to_idv4
from pydevp2p.utils import bytes_to_hex, bytes_to_int, framectx, int_to_bytes
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
protocolID = "discv5".encode('utf-8')

class Header:
    flag_types = ["MESSAGE", "WHOAREYOU", "HANDSHAKE"]
    STATIC_SIZE = 16 + 6 + 2 + 1 + 12 + 2
    def __init__(self, IV: bytes) -> None:
        self.IV = IV # sizeofMaskingIV ( 16 bytes )
        self.protocolID = None # 6 bytes
        self.version = None # uint16
        self.flag = None # 1 bytes (0, 1, 2)
        self.nonce = None  # 12 bytes
        self.authSize = None # uint16
        self.authData = None
        self.src = None # enode.ID 32 bytes pubk of src
    
    def __str__(self) -> str:
        ret = f"Discv5 Header:"
        for attr, val in self.__dict__.items():
            cleansedVal = val
            if isinstance(val, bytes):
                cleansedVal = bytes_to_hex(val) if len(val) > 6 else bytes_to_int(val)
            ret += f"\n  {attr.capitalize()}: {cleansedVal}"
        return ret
    
    def getValues(self) -> list[str]:
        ret = [len(self.__dict__.items())]
        for attr, val in self.__dict__.items():
            cleansedVal = val
            if isinstance(val, bytes):
                cleansedVal = bytes_to_hex(val) if len(val) > 8 else bytes_to_int(val)
            ret.append(f"{attr.capitalize()}: {cleansedVal}")
        return ret
    
    def getSize(self) -> int:
        return self.STATIC_SIZE + bytes_to_int(self.authSize)
        
    def setStaticHeader(self, staticHeader: bytes):
        self.protocolID = staticHeader[:6] # 6 bytes
        self.version = staticHeader[6:8] # uint16
        self.flag = staticHeader[8:9] # 1 bytes (0, 1, 2)
        self.nonce = staticHeader[9:21]  # 12 bytes
        self.authSize = staticHeader[21:23] # uint16
        self.type = self.flag_types[bytes_to_int(self.flag)]
        
    def getRawHeader(self) -> bytes:
        return self.IV + self.protocolID + self.version + self.flag + \
            self.nonce + self.authSize + self.authData
    
    def mask(self, destID: bytes):
        mask_key = destID[:16]
        ctr = Counter.new(len(mask_key) * 8, initial_value=bytes_to_int(self.IV))
        return AES.new(mask_key, AES.MODE_CTR, counter=ctr)
    
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
        if bytes_to_int(self.version) < minVersion:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Protocol Version, Expected {minVersion} Got {self.version}")
            return False
        if bytes_to_int(self.flag) != flagWhoareyou and packetLen < minMessageSize:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Msg Len, Expected {packetLen} < {minMessageSize}")
            return False
        if bytes_to_int(self.authSize) > packetLen:
            print(f"StaticHeader checkValid(packetLen) Err Invalid Auth Len, Expected {packetLen} < {self.authSize}")
            return False
        return True
    
class WhoareyouAuthData:
    SIZE = 16 + 8
    def __init__(self, authData: bytes) -> None:
        self.idNonce = authData[:16] # 16 bytes - ID proof data
        self.recordSeq = authData[16:self.SIZE] # uint64 (8 bytes) - Highest known ENR sequence of requester

class HandshakeAuthData:
    SIZE = 32 + 1 + 1 # Only h or { srcID, sigSize, pubkSize }
    def __init__(self, authData: bytes) -> None:
        self.srcEnodeId = authData[:32] # 32 bytes pubk
        self.sigSize = authData[32:33] # uint8 byte 8 bits
        self.pubkSize = authData[33:34] # uint8 byte 8 bits
        # Trailing variable-size data.
        self.sig: bytes = None
        self.pubk: bytes = None
        self.record: bytes = None

class MessageAuthData:
    SIZE = 32
    def __init__(self, srcEnodeId: bytes) -> None:
        self.srcEnodeId = srcEnodeId # 32 bytes pubk

class Discv5Codec:
    """
    Codec encodes and decodes Discovery v5 packets.
    This type is not safe for concurrent use.
    """
    sha256 = SHA256
    privk: bytes = None
    localEnodeID: bytes = None    
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
        self.localEnodeID = pubk_to_idv4(privtopub(privk))
        self.sc = SessionCache()
        return
    
    def __str__(self) -> str:
        return ""
    
    ########## DECODERS ##########
    
    def decode(self, input: bytes, fromAddr: str) -> tuple[Header | None, Packet | None, Session | None]:
        """Decode decodes a discovery v5 packet.

        Args:
            input (bytes): The raw data to decode, unmask, etc
            fromAddr (str): The address of who sent the discovery v5 packet

        Returns:
            tuple[bytes, Enode, Packet] | None: (srcPubk, Enode, Packet) or None if err occurs
        """
        if len(input) < minPacketSize:
            print(f"{framectx()} Discv5Codec decode(input, fromAddr) Err Invalid Packet Len, Expected >= {minPacketSize} Got {len(input)}")
            return None, None
        
        # Unmask the static header.
        head = Header(input[:sizeofMaskingIV])
        mask = head.mask(self.localEnodeID)
        staticHeader_masked = input[sizeofMaskingIV:Header.STATIC_SIZE]
        staticHeader_unmasked = mask.decrypt(staticHeader_masked)
        
        # Decode and verify the static header.
        head.setStaticHeader(staticHeader_unmasked)
        remainingInput = len(input) - Header.STATIC_SIZE
        if not head.checkValid(remainingInput):
            print(f"{framectx()} Discv5Codec decode(input, fromAddr) Err Static Header Invalid")
            return None, None
        
        # Unmask auth data
        authDataEnd = Header.STATIC_SIZE + bytes_to_int(head.authSize)
        authData_masked = input[Header.STATIC_SIZE:authDataEnd]
        authData_unmasked = mask.decrypt(authData_masked)
        head.authData = authData_unmasked
        
        # TODO Delete timed-out handshakes. This must happen before decoding to 
        # .. avoid processing the same handshake twice
        # self.sc.handshakeGC()
        
        # Decode auth part and message.
        headerData = head.getRawHeader()
        msgData = input[authDataEnd:]
        msgFlag = bytes_to_int(head.flag)        
        packet: Packet = None
        node: Enode = None
        session: Session = None
        if msgFlag == flagWhoareyou:
            # Had to make head.getRawHeader() instead of jus headerData???
            packet = self.decodeWhoareyou(head, headerData)
        elif msgFlag == flagHandshake:
            dec_handshake_msg = self.decodeHandshakeMessage(fromAddr, head, headerData, msgData)
            if dec_handshake_msg is not None:
                node, packet, session = dec_handshake_msg
        elif msgFlag == flagMessage:
            packet = self.decodeMessage(fromAddr, head, headerData, msgData)
        else:
            print(f"{framectx()} Discv5Codec decode(input, fromAddr) Err Invalid Msg Flag, Expected (0, 1, 2) Got {msgFlag}")
            return None
        
        return head, packet, session
    
    def decodeWhoareyou(self, head: Header, headerData: bytes) -> Packet | None:
        """decodeWhoareyou reads packet data after the header as a WHOAREYOU packet.

        Args:
            head (Header): The Header of the packet
            headerData (bytes): The raw Header Data

        Returns:
            Packet | None: Generic Packet or None if err occurs
        """
        if len(head.authData) != WhoareyouAuthData.SIZE:
            print(f"{framectx()} Discv5Codec decodeWhoareyou(head, headerData) Err Invalid Auth Size: Expected {WhoareyouAuthData.SIZE}, Got {len(head.authData)}")
            return None
        
        auth = WhoareyouAuthData(head.authData)
        p = Whoareyou(challengeData=headerData, nonce=head.nonce, idNonce=auth.idNonce, recordSeq=auth.recordSeq)
        return p
    
    def decodeHandshakeMessage(self, fromAddr: str, head: Header, headerData: bytes, msgData: bytes) -> tuple[Enode, Packet, Session] | None:
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
        node, auth, session, err = self.decodeHandshake(fromAddr, head)
        if err is not None:
            self.sc.deleteHandshake(auth.srcEnodeId, fromAddr)
            print(f"{framectx()} Discv5Codec decodeHandshakeMessage(fromAddr, head, headerData, msgData) Err Unable to Decode Handshake Message")
            return None
        
        # Decrypt the message using the new session keys
        msg = self.decryptMessage(msgData, head.nonce, headerData, session.readKey)
        if msg is None:
            self.sc.deleteHandshake(auth.srcEnodeId, fromAddr)
            print(f"{framectx()} Discv5Codec decodeHandshakeMessage(fromAddr, head, headerData, msgData) Err Unable to Decrypt Handshake Message")
            return None
        
        # Handshake OK, drop the challenge and store the new session keys
        self.sc.storeNewSession(auth.srcEnodeId, fromAddr, session)
        self.sc.deleteHandshake(auth.srcEnodeId, fromAddr)
        return node, msg, session
    
    def decodeHandshake(self, fromAddr: str, head: Header) -> tuple[Enode | None, HandshakeAuthData | None, Session | None, str | None]:
        """Decodes a discovery v5 handshake packet returning the src enode ID (pubk) and ENRRecord
        along with the decoded Packet

        Args:
            fromAddr (str): The ip address of the sender of this packet
            head (Header): The Header of this packet

        Returns:
            tuple[Enode, HandshakeAuthData, Session] | None: (Enode, HandshakeAuthData, Session) or None
        """
        auth = self.decodeHandshakeAuthData(head)
        if auth is None:
            err = f"{framectx()} Discv5Codec decodeHandshake(fromAddr, head) Err Unable to Decode Auth Data"
            print(err)
            return None, auth, None, err
        
        # Verify against the last WHOAREYOU
        challenge: Whoareyou = self.sc.getHandshake(auth.srcEnodeId, fromAddr)
        if challenge is None:
            err = f"{framectx()} Discv5Codec decodeHandshake(fromAddr, head) Err Unable to Retrieve Challenge from a Previous WHOAREYOU"
            print(err)
            return None, auth, None, err
        
        # Get node record
        n = self.decodeHandshakeRecord(challenge.node, auth.srcEnodeId, auth.record)
        if n  is None:
            err = f"{framectx()} Discv5Codec decodeHandshake(fromAddr, head) Err Unable to Decode Handshake Record"
            print(err)
            return None, auth, None, err
            
        # Verify ID nonce signature
        sig = auth.sig
        cdata = challenge.challengeData
        if not verifyIDSignature(self.sha256, sig, n, cdata, auth.pubk, self.localEnodeID):
            err = f"{framectx()} Discv5Codec decodeHandshake(fromAddr, head) Err Unable to Verify ID Signature"
            print(err)
            return None, auth, None, err
        
        # Verify ephemeral key is on curve
        ephkey = decodePubk(auth.pubk)
        if not ephkey:
            err = f"{framectx()} Discv5Codec decodeHandshake(fromAddr, head) Err Unable to Decode Ephemeral Key"
            print(err)
            return None, auth, None, err
    
        # Derive the session keys
        session = deriveKeys(self.sha256, self.privk, ephkey, auth.srcEnodeId, self.localEnodeID, cdata)
        session = session.keysFlipped()
            
        return n, auth, session, None
    
    def decodeHandshakeAuthData(self, head: Header) -> HandshakeAuthData | None:
        """decodeHandshakeAuthData reads the authdata section of a handshake packet.

        Args:
            head (Header): Header of the handshake packet

        Returns:
            HandshakeAuthData | None: Decoded Handshake Auth Data or None on err
        """
        # Decode fixed size part
        if len(head.authData) < HandshakeAuthData.SIZE:
            print(f"{framectx()} Discv5Codec decodeHandshakeAuthData(head) Err Invalid Auth Size: Expected {HandshakeAuthData.SIZE}, Got {len(head.authData)}")
            return None
        
        auth = HandshakeAuthData(head.authData)
        head.src = auth.srcEnodeId
        
        # Decode variable-size part
        vardata = head.authData[HandshakeAuthData.SIZE:]
        sigAndKeySize = bytes_to_int(auth.sigSize) + bytes_to_int(auth.pubkSize)
        keyOffset = bytes_to_int(auth.sigSize)
        recOffset = keyOffset + bytes_to_int(auth.pubkSize)
        
        if len(vardata) < sigAndKeySize:
            print(f"{framectx()} Discv5Codec decodeHandshakeAuthData(head) Err Invalid Vardata Len: Expected {len(vardata)} >= {sigAndKeySize}")
            return auth
        
        auth.sig = vardata[:keyOffset]
        auth.pubk = vardata[keyOffset:recOffset]
        auth.record = vardata[recOffset:]
        return auth
    
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
        node = local
        if len(remote) > 0:
            dec_record = decode(remote, strict=False)
            record = Record(dec_record)
            if local is None:
                n = Enode(record, record.pubk)
                if n.pubk is None:
                    print(f"{framectx()} Discv5Codec decodeHandshakeRecord(local, wantID, remote) Err Unable to Create ENode")
                    return None
                if n.pubk != wantID:
                    print(f"{framectx()} Discv5Codec decodeHandshakeRecord(local, wantID, remote) Err Found Different ID than Record in Handshake")
                    return None
                node = n
        if node is None:
            print(f"{framectx()} Discv5Codec decodeHandshakeRecord(local, wantID, remote) Err No ENR Record Found")
            return None
        
        return node
    
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
        if len(head.authData) != MessageAuthData.SIZE:
            print(f"{framectx()} Discv5Codec decodeMessage(fromAddr, head, headerData, msgData) Err Invalid Auth Size: Expected {MessageAuthData.SIZE}, Got {len(head.authData)}")
            return None
        
        auth = MessageAuthData(head.authData)
        head.src = auth.srcEnodeId
        
        # Try decrypting the message
        key = self.sc.readKey(auth.srcEnodeId, fromAddr)
        if key is None:
            print(f"Discv5Codec decodeMessage(fromAddr, head, headerData, msgData) No Known Key for {fromAddr} Initiate Handshake")
            return Unknown(head.nonce)
        msg = self.decryptMessage(msgData, head.nonce, headerData, key)
        
        return msg
    
    def decryptMessage(self, input: bytes, nonce: bytes, headerData: bytes, readKey: bytes | None) -> Packet | None:
        """Decrypts a message using AES-GCM with the key, nonce, input and headerData

        Args:
            input (bytes): The ciphertext to decrypt
            nonce (bytes): Given Nonce value
            headerData (bytes): The Auth data used
            readKey (bytes): The AES key

        Returns:
            Packet | None: The decrypted Packet or None if err
        """
        # print("input:", bytes_to_hex(input))
        # print("nonce:", bytes_to_hex(nonce))
        # print("headerData:", bytes_to_hex(headerData))
        # print("readKey:", bytes_to_hex(readKey))
        # print()
        msgdata = decryptGCM(readKey, nonce, input, headerData)
        if msgdata is None or len(msgdata) == 0:
            print(f"{framectx()} Discv5Codec decryptMessage(input, nonce, headerData, readKey) Err Unable to Decrypt Packet")
            return None
        
        return decodeMessageByType(msgdata[0], msgdata[1:])
        
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
        
