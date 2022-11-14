import snappy
from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Util import Counter
from rlp.codec import decode

from pydevp2p.crypto.ecies import generate_shared_secret
from pydevp2p.crypto.params import ECIES_AES128_SHA256
from pydevp2p.crypto.secp256k1 import privtopub, recover_pubk, unmarshal
from pydevp2p.crypto.utils import keccak256Hash, xor
from pydevp2p.rlpx.capabilities import RLPxCapabilityMsg
from pydevp2p.utils import bytes_to_hex, ceil16, read_uint24

# Handshake Relates Types / Classes

SSK_LEN = 16 # max shared key length (pubkey) / 2
SIG_LEN = 65 # elliptic S256 secp256k1
PUB_LEN = 64 # 512 bit pubkey in uncompressed format
SHA_LEN = 32 # Hash Length (for nonce, etc)

class AuthMsgV4:
    """RLPx v4 handshake auth (defined in EIP-8)."""
    def __init__(self, msg: list[bytes]) -> None:
        # Should call validate before creating this object
        self.Signature, self.InitatorPubkey, self.Nonce, self.Version, *extra = msg
        self.RandomPrivKey = extra[0] if len(extra) > 0 else None
            
    def __str__(self) -> str:
        signature = f"Signature:\t\t{bytes_to_hex(self.Signature)}"
        initPubK = f"InitatorPubkey:\t{bytes_to_hex(self.InitatorPubkey)}"
        nonce = f"Nonce:\t\t{bytes_to_hex(self.Nonce)}"
        version = f"Version:\t\t{bytes_to_hex(self.Version)}"
        randPrivk = f"RandomPrivKey:\t{bytes_to_hex(self.RandomPrivKey)}"
        return f"AuthMsgV4:\n  {signature}\n  {initPubK}\n  {nonce}\n  {version}\n  {randPrivk}"
    
    def getValues(self) -> list[str]:
        return [
            5,
            f"Signature: {bytes_to_hex(self.Signature)}",
            f"InitatorPubkey: {bytes_to_hex(self.InitatorPubkey)}",
            f"Nonce: {bytes_to_hex(self.Nonce)}",
            f"Version: {bytes_to_hex(self.Version)}",
            f"RandomPrivKey: {bytes_to_hex(self.RandomPrivKey)}"
        ]
        
        # return {
        #     "Signature": bytes_to_hex(self.Signature), 
        #     "InitatorPubkey": bytes_to_hex(self.InitatorPubkey),
        #     "Nonce": bytes_to_hex(self.Nonce),
        #     "Version": bytes_to_hex(self.Version),
        #     "RandomPrivKey": bytes_to_hex(self.RandomPrivKey)
        # }
    
    @staticmethod
    def validate(msg: list[bytes]) -> bool:
        if len(msg) < 4:
            return False
        if len(msg[0]) != SIG_LEN or len(msg[1]) != PUB_LEN or len(msg[2]) != SHA_LEN or len(msg[3]) != 1:
            return False
        return True
    
    
class AuthRespV4:
    """RLPx v4 handshake response (defined in EIP-8)."""
    def __init__(self, msg: list[bytes]) -> None:
        # Should call validate before creating this object
        self.RandomPubkey, self.Nonce, self.Version, *extra = msg
        self.RandomPrivKey = extra[0] if len(extra) > 0 else None
            
    def __str__(self) -> str:
        randPubKey = f"RandomPubkey:\t\t{bytes_to_hex(self.RandomPubkey)}"
        nonce = f"Nonce:\t\t{bytes_to_hex(self.Nonce)}"
        version = f"Version:\t\t{bytes_to_hex(self.Version)}"
        randPrivk = f"RandomPrivKey:\t{bytes_to_hex(self.RandomPrivKey)}"
        return f"AuthRespV4:\n  {randPubKey}\n  {nonce}\n  {version}\n  {randPrivk}"
        
    def getValues(self) -> dict[str, str]:
        return [
            4,
            f"RandomPubkey: {bytes_to_hex(self.RandomPubkey)}",
            f"Nonce: {bytes_to_hex(self.Nonce)}",
            f"Version: {bytes_to_hex(self.Version)}",
            f"RandomPrivKey: {bytes_to_hex(self.RandomPrivKey)}"
        ]
        # return {
        #     "RandomPubkey": bytes_to_hex(self.RandomPubkey), 
        #     "Nonce": bytes_to_hex(self.Nonce),
        #     "Version": bytes_to_hex(self.Version),
        #     "RandomPrivKey": bytes_to_hex(self.RandomPrivKey)
        # }
    
    @staticmethod
    def validate(msg: list[bytes]) -> bool:
        if len(msg) < 3:
            return False
        if len(msg[0]) != PUB_LEN or len(msg[1]) != SHA_LEN or len(msg[2]) != 1:
            return False
        return True
    
    
class Secrets:
    """
    Secrets represents the connection secrets which are negotiated during the handshake.
    """
    def __init__(self, pubk: bytes, ephemeral_key: bytes, shared_secret: bytes, aes_secret: bytes, mac_secret: bytes) -> None:
        self.remotePubk = pubk # remote-static-pubk
        self.ephemeral_key = ephemeral_key
        self.shared_secret = shared_secret
        self.aes = aes_secret
        self.mac = mac_secret
        self.hashalgo = keccak
        self.egressMac = keccak.new(digest_bits=256)
        self.ingressMac = keccak.new(digest_bits=256)
                    
    def __str__(self) -> str:
        remotePubk = f"remotePubk:\t{bytes_to_hex(self.remotePubk)}"
        ephemeralKey = f"ephemeralKey:\t{bytes_to_hex(self.ephemeral_key)}"
        sharedSecret = f"sharedSecret:\t{bytes_to_hex(self.shared_secret)}"
        aes = f"aes:\t\t{bytes_to_hex(self.aes)}"
        mac = f"mac:\t\t{bytes_to_hex(self.mac)}"
        hashalgo = f"hashalgo:\t{self.hashalgo.__name__}"
        egressMac = f"egressMac:\t{bytes_to_hex(self.egressMac.digest())}"
        ingressMac = f"ingressMac:\t{bytes_to_hex(self.ingressMac.digest())}"
        return f"Secrets:\n  {remotePubk}\n  {ephemeralKey}\n  {sharedSecret}\n  {aes}\n  {mac}\n  {hashalgo}\n  {egressMac}\n  {ingressMac}"
    
        
    
class HandshakeState:
    """
    HandshakeState holds all of the valuable information during an active
    handshake between two nodes. After a successful handshake, the two nodes
    pull out all of the secrets that they shared via the handshake
    """
    def __init__(self, init: bool, remotePubk: bytes | None = None) -> None:
        self.initiator = init
        self.remotePubk = remotePubk # static remote public key (non-changing)
        self.initNonce = None  # nonce sent from the initiator of the handshake
        self.respNonce = None  # nonce sent by the respondant of the auth msg
        # the ephemeral-priv-key (ecdhe-random-key)
        # .. If initiator, generated right before encryption (also creates signature)
        # .. If recipient, generate right after decrypting/decoding AuthMsg and before
        # .... creating the AuthResponse msg
        self.randomPrivk = None
        # the ephemeral-public-key (ecdhe-random-pubk)
        # .. If initiator, remote-random-pubk comes from the AuthResponse data
        # .. If recipient, remote-random-pubk comes from the ecdsa pubk recovery from
        # .... the signature of the AuthMsg: p2p/rlpx/rlpx.go line # 458 -> 467
        # .... ALGO: static_shared_secret = crypto/ecies/generate_shared_secret( remotePubk, privk )
        # .... ALGO: signedMsg = xor( static_shared_secret, self.initNonce )
        # .... ALGO: remoteRandomPub = crypto/secp256k1/signature_to_pubk( signedMsg, AuthMsgV4.Signature )
        # .... NOTE in short, this requires that the recipiant know their randomPrivK to derive the remoteRandomPubk
        self.remoteRandomPubk = None
         # temp - this is the privk that is forced in the handshake msg (Also the privk to decrypt msgs)
        self.remoteRandomPrivk = None
                    
    def __str__(self) -> str:
        initiator = f"initiator:\t\t{self.initiator}"
        remotePubk = f"remotePubk:\t\t{bytes_to_hex(self.remotePubk)}"
        initNonce = f"initNonce:\t\t{bytes_to_hex(self.initNonce)}"
        respNonce = f"respNonce:\t\t{bytes_to_hex(self.respNonce)}"
        randomPrivk = f"randomPrivk:\t\t{bytes_to_hex(self.randomPrivk)}"
        remoteRandomPubk = f"remoteRandomPubk:\t{bytes_to_hex(self.remoteRandomPubk)}"
        remoteRandomPrivk = f"remoteRandomPrivk:\t{bytes_to_hex(self.remoteRandomPrivk)}"
        return f"HandshakeState:\n  {initiator}\n  {remotePubk}\n  {initNonce}\n  {respNonce}\n  {randomPrivk}\n  {remoteRandomPubk}\n  {remoteRandomPrivk}"
    
    def staticSharedSecret(self, privk: bytes) -> bytes:
        return generate_shared_secret(self.remotePubk, privk)
    
    def handleAuthMsg(self, msg: AuthMsgV4, privk: bytes) -> bytes | None:
        self.initNonce = msg.Nonce
        self.remotePubk = unmarshal(msg.InitatorPubkey)
        
        #######################
        # otherNode's self.randomPrivk is pulled here
        if hasattr(msg, "RandomPrivKey"):
            # This is actually the random priv key of the one who sent this message
            self.remoteRandomPrivk = msg.RandomPrivKey
        #######################
        
        # Check the signature.
        token = self.staticSharedSecret(privk)
        if token is None:
            print("HandshakeState handleAuthMsg(msg, privk) Err Static Shared Secret None")
            return None
        
        signedMsg = xor(token, self.initNonce)
        if len(signedMsg) != 32:
            print("Invalid signedMsg len")
            return None
        
        self.remoteRandomPubk = recover_pubk(signedMsg, msg.Signature)

        return self.remoteRandomPubk
    
    def handleAuthResp(self, msg: AuthRespV4) -> bytes | None:
        self.respNonce = msg.Nonce
        self.remoteRandomPubk = msg.RandomPubkey
        if hasattr(msg, "RandomPrivKey"):
            self.remoteRandomPrivk = msg.RandomPrivKey
        return self.remoteRandomPubk
    
    def secrets(self, auth: bytes, authResp: bytes) -> Secrets | None:
        if self.randomPrivk is None or self.remoteRandomPubk is None:
            print("HandshakeState secrets(auth, authResp) Error randomPrivk or remoteRandomPubk is None")
            return None
        
        if self.initNonce is None or self.respNonce is None:
            print("HandshakeState secrets(auth, authResp) Error initNonce or respNonce is None")
            return None
            
        # 1) Creates the ephemeral-key (ecdheSecret) using:
        # .... The ephemeral-privkey (randomPrivKey) and remote-ephemeral-pubk (remoteRandomPub)
        ephemeral_key = generate_shared_secret(self.remoteRandomPubk, self.randomPrivk)
        if ephemeral_key is None:
            return None
                
        # 2) Derives the shared-secret from the ephermeral key agreement
        # .... shared-secret = keccak256hash( ephemeral-key, keccak256hash( respNonce, initNonce ) )
        shared_secret = keccak256Hash(ephemeral_key + keccak256Hash(self.respNonce + self.initNonce))
        # 3) Calculate the aes-secret using the hash of both the ephemeral-key and shared-secret
        # .... aes-secret = keccak256hash( ephemeral-secret, shared-secret )
        aes_secret = keccak256Hash(ephemeral_key + shared_secret)
        
        # 4) Calculate the mac-secret with the hash of both the ephemeral-key and aes-key
        # .... mac-secret = keccak256hash( ephemeral-secret, aes-secret )
        mac_secret = keccak256Hash(ephemeral_key + aes_secret)
        
        # 5) Lastly, calculate the Egress and Ingress MACs (depending on if initiator or not)
        s = Secrets(self.remotePubk, ephemeral_key, shared_secret, aes_secret, mac_secret)
        # mac1 = keccak.update( xor( mac_secret, respNonce ) ).update( authData )
        mac1 = s.hashalgo.new(digest_bits=256)
        mac1.update(xor(mac_secret, self.respNonce))
        mac1.update(auth)
        # mac2 = keccak.update( xor( mac_secret, initNonce ) ).update( AuthRespData )
        mac2 = s.hashalgo.new(digest_bits=256)
        mac2.update(xor(mac_secret, self.initNonce))
        mac1.update(authResp)
        if self.initiator:
            s.egressMac, s.ingressMac = mac1, mac2
        else:
            s.egressMac, s.ingressMac = mac2, mac1

        return s


# RLPx Frame Relates Types / Classes
#######################################################################################

class RLPxInitMsgv5:
    """First packet sent over the connection, and sent once by both sides. No other 
    messages may be sent until a Hello is received. Implementations must ignore any 
    additional list elements in Hello because they may be used by a future version."""
    msg_types = ["Hello", "Disconnect", "Ping", "Pong"]
    
    def __init__(self, code: int, msg: list[bytes]) -> None:
        self.code = code
        self.type = self.msg_types[code]
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
    def __init__(self, secrets: Secrets) -> None:
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
        
    def readFrame(self, data: bytes) -> RLPxInitMsgv5 | RLPxCapabilityMsg | None:
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
        print("header:", header.hex())
        if header is None:
            print(f"SessionState readFrame(data) Err Unable to Decrypt Header: {bytes_to_hex(data[:headerSize])}")
            return None
        
        # Get the frame size from the first 3 bytes
        frameSize = read_uint24(header)
        # frameSize = struct.unpack(b'>I', b'\x00' + header[:3])[0]
        print("frameSize:", frameSize, ceil16(frameSize))
        
        # Round up frame size to 16 byte boundary for padding
        readSize = ceil16(frameSize)
        
        # Decrypt and verify frame-ciphertext and frame-mac
        frame = self._decryptBody(data[headerSize:], readSize)
        # print("frame[:frameSize]:", bytes_to_hex(frame[:frameSize]))
        if frame is None:
            print(f"SessionState readFrame(data) Err Unable to Decrypt Frame: {bytes_to_hex(data[headerSize:])}")
            return None

        # The first RLPx message after handshake should always be a Hello msg
        if not self.handshakeCompleted:
            code = frame[0] - 128
            # print("code:", code)
            
            dec_frame = decode(frame[1:frameSize], strict=False)
            if dec_frame is None:
                print("SessionState readFrame(data) Err Unable to Decode Frame")
        
            if not RLPxInitMsgv5.validate(code, dec_frame):
                print(f"SessionState readFrame(data) Err Unable to Validate RLPxInitMsgv5 {code}: {dec_frame}")
                return None
            self.handshakeCompleted = True
            
            return RLPxInitMsgv5(code, dec_frame)
        
        # Snappy Decompression
        code, decompress = frame[0], snappy.decompress(frame[1:frameSize])
        # print(f"code: {code}, Decompressed:", bytes_to_hex(decompress)) 
        
        # RLP Decoding
        dec_decompress = decode(decompress, strict=False)
        # print("Decompressed Data:", dec_decompress)
        
        # check for code 1,2,3 (DISCONNECT, PING, PONG)
        if code == 1 or code == 2 or code == 3:
            if not RLPxInitMsgv5.validate(code, dec_decompress):
                print(f"SessionState readFrame(data) Err Unable to Validate RLPxInitMsgv5 {code}: {dec_decompress}")
                return None
            return RLPxInitMsgv5(code, dec_decompress)
        
        # TODO This is now where each capability splits off and has their own messaging scheme
        # .. Looks like there really is only ETH and SNAP caps in this network
        # .. https://github.com/ethereum/devp2p/tree/master/caps
        
        return RLPxCapabilityMsg(dec_decompress)
        
    def writeFrame(self, code: int, data: bytes) -> bytes | None:
        # Place holder
        return
