import secrets
import snappy
from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Util import Counter
from rlp.codec import decode
from rlp.sedes import big_endian_int

from pydevp2p.crypto.params import ECIES_AES128_SHA256
from pydevp2p.rlpx.capabilities import RLPxCapabilityMsg, get_rlpx_capability_msg
from pydevp2p.utils import bytes_to_hex, ceil16, read_uint24


class RLPxP2PMsg:
    """First packet sent over the connection, and sent once by both sides. No other 
    messages may be sent until a Hello is received. Implementations must ignore any 
    additional list elements in Hello because they may be used by a future version."""
    msg_types = ["Hello", "Disconnect", "Ping", "Pong"]
    
    def __init__(self, code: int, msg: list[bytes]) -> None:
        self.code = code
        self.type = self.msg_types[code]
        print()
        print(f"P2P: {code}, {self.type}:", msg)
        if code == 0:
            protocolVersion, clientId, capabilities, listenPort, nodeKey, *self.other = msg
            self.protocolVersion = protocolVersion[0]
            self.clientId = clientId.decode("utf-8")
            self.listenPort = listenPort.decode("utf-8") if len(listenPort) > 0 else "N/A"
            self.nodeKey = nodeKey
            self.capabilities = []
            for capability in capabilities:
                name = capability[0].decode("utf-8")
                version = capability[1][0]
                self.capabilities.append(f"{name}: {version}")
            self.capabilities = ", ".join(self.capabilities)
        elif code == 1:
            self.reason = msg[0]
            
    def __str__(self) -> str:
        ret = ""
        vals = self.getValues()
        for i in range(1, len(vals)):
            ret += f"  {vals[i]}\n"
        return f"RLPxInitMsgv5:\n{ret}"
            
    def getValues(self) -> list[str]:
        ret = [
            2,
            f"Type: {self.type}",
            f"Code: {self.code}",
        ]
        if self.code == 0:
            ret.append(f"ProtocolVersion: {self.protocolVersion}")
            ret.append(f"ClientId: {self.clientId}")
            ret.append(f"Capabilities: {self.capabilities}")
            ret.append(f"ListenPort: {self.listenPort}")
            ret.append(f"NodeKey: {bytes_to_hex(self.nodeKey)}")
            ret[0] = 7
        elif self.code == 1:
            ret.append(f"Reason: {self.reason}")
            ret[0] = 3
        return ret
            
        
    @staticmethod
    def validate(code: int, msg: list[bytes]) -> bool:
        if code < 0:
            print("RLPxCapabilityMsgv5 validate(code, msg) Err Invalid Msg Code")
            return False
        if code > 3:
            print("RLPxCapabilityMsgv5 validate(code, msg) Err Unsupported Msg Code")
            return False
        if code == 0 and len(msg) >= 5:
            # Check valid Hello Msg
            return True
        elif code == 1 and len(msg) == 1:
            # Check valid Disconnect Msg
            return True
        elif code == 1 and len(msg) == 1:
            # Check valid Disconnect Msg
            return True
        elif len(msg) == 0:
            # Check valid Ping/Pong Msg
            return True
        print("RLPxCapabilityMsgv5 validate(code, msg) Err Invalid Msg")
        return False

class HashMAC:
    """HashMAC holds the state of the RLPx v4 MAC contraption"""
    def __init__(self) -> None:
        self.cipher = None
        self.hash = keccak.new(digest_bits=256)
        self.aesBuffer = [b'\x00'] * 16
        self.hashBuffer = [b'\x00'] * 32
        self.seedBuffer = [b'\x00'] * 32
        
    def computeHeader(self, header: bytes) -> bytes:
        return
    
    def computeFrame(self, framedata: bytes) -> bytes:
        return
    
    def computer(self, sum1: bytes, seed: bytes) -> bytes:
        return

class SessionState:
    """Contains the session keys"""
    def __init__(self, secrets: secrets) -> None:
        self.params = ECIES_AES128_SHA256()
        self.ctr = Counter
        self.cipher = self.params.Cipher
        # all you need to call instead of .XORKeyStream is just .decrypt(ct) or .encrypt(m)
        # 0 IV because the key for encryption is ephemeral
        enc_ctr = Counter.new(self.params.BlockSize * 8, initial_value=0)
        self.enc = self.cipher.new(secrets.aes, self.params.Cipher.MODE_CTR, counter=enc_ctr)
        # 0 IV because the key for encryption is ephemeral
        dec_ctr = Counter.new(self.params.BlockSize * 8, initial_value=0)
        self.dec = AES.new(secrets.aes, self.params.Cipher.MODE_CTR, counter=dec_ctr)
        self.egressMac = HashMAC()
        self.ingressMac = HashMAC()
        self.handshakeCompleted = False
        
    def _decryptHeader(self, headerData: bytes) -> bytes | None:
        if len(headerData) != 32:
            print("SessionState _decryptHeader(headerData) Err Invalid headerData Len")
            return None
        
        header_ciphertext = headerData[:16]
        header_mac = headerData[16:]
        
        if len(header_mac) != 16:
            print("SessionState _decryptHeader(headerData) Err Invalid MAC Len")
            return None
        
        # TODO verify header_mac
        
        return self.dec.decrypt(header_ciphertext)
    
    def _decryptBody(self, bodyData: bytes, readSize: int) -> bytes | None:
        if not len(bodyData) >= readSize + 16:
            print(f"SessionState _decryptBody(bodyData, readSize) Err Insufficient Body Len {len(bodyData)}, Expected {len(bodyData)} >= {readSize + 16}")
            return None
        
        frame_ciphertext = bodyData[:readSize]
        frame_mac = bodyData[readSize: readSize + 16]
        
        if len(frame_mac) != 16:
            print("SessionState _decryptBody(bodyData, readSize) Err Invalid MAC Len")
            return None
            
        # TODO verify frame_mac
        
        return self.dec.decrypt(frame_ciphertext) 
        
    def readFrame(self, data: bytes) -> RLPxP2PMsg | RLPxCapabilityMsg | None:
        """SessionState readFrame reads and decrypts message frames, which are all
        messages that follow the initial handshake. A frame carries a single encrypted
        message belonging to a capability. This function allows for both decrypting
        and verification of frame data.
        
        https://github.com/ethereum/devp2p/blob/master/rlpx.md
        
        Hello: frame-data = msg-id || msg-data
        All messages following Hello are compressed using the Snappy algorithm.
        After: frame-data = msg-id || snappyCompress(msg-data)

        Args:
            data (bytes): The encrypted message frame to be decrypted and verified

        Returns:
            bytes | None: The decrypted message frame or None if an error occurred
        """
        headerSize = 32
        # Read the frame header
        header = self._decryptHeader(data[:headerSize])
        # print("header:", header.hex())
        if header is None:
            print(f"SessionState readFrame(data) Err Unable to Decrypt Header: {bytes_to_hex(data[:headerSize])}")
            return None
        
        # Get the frame size from the first 3 bytes
        frameSize = read_uint24(header)
        # frameSize = struct.unpack(b'>I', b'\x00' + header[:3])[0]
        # print("frameSize:", frameSize, ceil16(frameSize))
        
        # Round up frame size to 16 byte boundary for padding
        readSize = ceil16(frameSize)
        
        # Decrypt and verify frame-ciphertext and frame-mac
        frame = self._decryptBody(data[headerSize:], readSize)
        # print("frame[:frameSize]:", bytes_to_hex(frame[:frameSize]))
        if frame is None:
            print(f"SessionState readFrame(data) Err Unable to Decrypt Frame: {bytes_to_hex(data[headerSize:])}")
            return None
        
        code = decode(frame[:1], sedes=big_endian_int, strict=False)

        # The first RLPx message after handshake should always be a Hello msg
        if not self.handshakeCompleted:
            dec_frame = decode(frame[1:frameSize], strict=False)
            if dec_frame is None:
                print("SessionState readFrame(data) Err Unable to Decode Frame")
        
            if not RLPxP2PMsg.validate(code, dec_frame):
                print(f"SessionState readFrame(data) Err Unable to Validate RLPxP2PMsg {code}: {dec_frame}")
                return None
            self.handshakeCompleted = True
            
            # TODO Msg ids are layed out in blocks based on capability name/version and are calculated by each
            # .. peer from their capability lists in the Hello msg. 

            return RLPxP2PMsg(code, dec_frame)
        
        # Snappy Decompression
        decompress = snappy.decompress(frame[1:frameSize])
        # print(f"code: {code}, Decompressed:", bytes_to_hex(decompress)) 
        
        # RLP Decoding
        dec_decompress = decode(decompress, strict=False)
        # print("Decompressed Data:", dec_decompress)
        
        # check for code 1,2,3 (DISCONNECT, PING, PONG)
        if code == 1 or code == 2 or code == 3:
            if not RLPxP2PMsg.validate(code, dec_decompress):
                print(f"SessionState readFrame(data) Err Unable to Validate RLPxP2PMsg {code}: {dec_decompress}")
                return None
            return RLPxP2PMsg(code, dec_decompress)
        
        # TODO This is now where each capability splits off and has their own messaging scheme
        # .. https://github.com/ethereum/devp2p/tree/master/caps
        return get_rlpx_capability_msg(code, dec_decompress)
        
    def writeFrame(self, code: int, data: bytes) -> bytes | None:
        # Place holder
        return
