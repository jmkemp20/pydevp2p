from pydevp2p.crypto.ecies import generate_shared_secret
from pydevp2p.crypto.params import ECIES_AES128_SHA256
from pydevp2p.crypto.secp256k1 import privtopub, recover_pubk, signature_to_pubk, unmarshal
from pydevp2p.crypto.utils import keccak256Hash, xor
from pydevp2p.utils import bytes_to_hex, hex_to_bytes
from Crypto.Hash import keccak
from Crypto.Util import Counter 

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
    
    def getValues(self) -> dict[str, str]:
        return {
            "Signature": bytes_to_hex(self.Signature), 
            "InitatorPubkey": bytes_to_hex(self.InitatorPubkey),
            "Nonce": bytes_to_hex(self.Nonce),
            "Version": bytes_to_hex(self.Version),
            "RandomPrivKey": bytes_to_hex(self.RandomPrivKey)
        }
    
    @staticmethod
    def validate(msg: list[bytes]) -> False:
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
        return {
            "RandomPubkey": bytes_to_hex(self.RandomPubkey), 
            "Nonce": bytes_to_hex(self.Nonce),
            "Version": bytes_to_hex(self.Version),
            "RandomPrivKey": bytes_to_hex(self.RandomPrivKey)
        }
    
    @staticmethod
    def validate(msg: list[bytes]) -> False:
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
        # self.randomPrivk is generated here.....
        if hasattr(msg, "RandomPrivKey"):
            # This is actually the random priv key of the one who sent this message
            self.remoteRandomPrivk = msg.RandomPrivKey
            print("remoteRandomPrivk pub:", bytes_to_hex(privtopub(self.remoteRandomPrivk)))
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
        self.params = ECIES_AES128_SHA256
        self.ctr = Counter
        self.cipher = self.params.Cipher
        # all you need to call instead of .XORKeyStream is just .decrypt(ct) or .encrypt(m)
        # 0 IV because the key for encryption is ephemeral
        enc_ctr = Counter.new(self.params.BlockSize * 8, initial_value=0)
        self.enc = self.cipher.new(secrets.aes, self.params.Cipher.MODE_CTR, counter=enc_ctr)
        # 0 IV because the key for encryption is ephemeral
        dec_ctr = Counter.new(self.params.BlockSize * 8, initial_value=0)
        self.dec = self.cipher.new(secrets.aes, self.params.Cipher.MODE_CTR, counter=dec_ctr)
        self.egressMac = HashMAC()
        self.ingressMac = HashMAC()
        
    def readFrame(self, data: bytes) -> bytes | None:
        """SessionState readFrame reads and decrypts message frames, which are all
        messages that follow the initial handshake. A frame carries a single encrypted
        message belonging to a capability. This function allows for both decrypting
        and verification of frame data.
        
        After decryption, the decrypted returned bytes are then RLP decoded and/or 
        decompressed w/ SNAPPY

        Args:
            data (bytes): The encrypted message frame to be decrypted and verified

        Returns:
            bytes | None: The decrypted message frame or None if an error occurred
        """
        headerSize = 32
        # Read the frame header
        header = data[:headerSize]
        if header is None:
            return None
        
        # Verify header MAC. TODO
        # wantHeaderMac = self.ingressMac.computeHeader(header[:16])
        # if wantHeaderMac != header[16:]:
        #     print("SessionState readFrame(data) Err Bad Header MAC")
        #     return None
        
        # Decrypt the frame header to get the frame size
        frameSize = self.dec.decrypt(header[:int(headerSize / 2)])
        
        # Frame size must be rounded up to 16 byte boundary for padding
        realSize = frameSize
        padding = frameSize % 16
        if padding > 0:
            realSize += 16 - padding
            
        # Read the frame content
        frame = data[headerSize:headerSize + int(realSize)]
        if frame is None:
            return None
        
        # Validate the frame MAC TODO
        # frameMAC = data[headerSize + int(realSize):headerSize + int(realSize) + 16]
        # wantFrameMAC = self.ingressMac.computeFrame(frame)
        # if wantFrameMAC != frameMAC:
        #     print("SessionState readFrame(data) Err Bad Frame MAC")
        #     return None
        
        # Decrypt the frame data
        frameDec = self.dec.decrypt(frame)
        return frameDec[:frameSize]
        
    def writeFrame(self, code: int, data: bytes) -> bytes | None:
        # Place holder
        return
