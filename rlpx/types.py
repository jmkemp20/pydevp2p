from pydevp2p.crypto.params import ECIES_AES128_SHA256
from pydevp2p.utils import bytes_to_hex
from Crypto.Hash import keccak
from Crypto.Util import Counter 

# Handshake Relates Types / Classes

SSK_LEN = 16 # max shared key length (pubkey) / 2
SIG_LEN = 65 # elliptic S256 secp256k1
PUB_LEN = 64 # 512 bit pubkey in uncompressed format
SHA_LEN = 32 # Hash Length (for nonce, etc)

class AuthMsgV4:
    """RLPx v4 handshake auth (defined in EIP-8)."""
    def __init__(self, msg: bytes) -> None:
        # Should call validate before creating this object
        self.Signature = msg[0]
        self.InitatorPubkey = msg[1]
        self.Nonce = msg[2]
        self.Version = msg[3]
            
    def __str__(self) -> str:
        signature = f"Signature:\t\t{bytes_to_hex(self.Signature)}"
        initPubK = f"InitatorPubkey:\t{bytes_to_hex(self.InitatorPubkey)}"
        nonce = f"Nonce:\t\t{bytes_to_hex(self.Nonce)}"
        version = f"Version:\t\t{bytes_to_hex(self.Version)}"
        return f"AuthMsgV4:\n  {signature}\n  {initPubK}\n  {nonce}\n  {version}"
    
    @staticmethod
    def validate(msg: list[bytes]) -> False:
        if len(msg) < 4:
            return False
        if len(msg[0]) != SIG_LEN or len(msg[1]) != PUB_LEN or len(msg[2]) != SHA_LEN or len(msg[3]) != 1:
            return False
        return True
    
    
class AuthRespV4:
    """RLPx v4 handshake response (defined in EIP-8)."""
    def __init__(self, msg: bytes) -> None:
        # Should call validate before creating this object
        self.RandomPubkey = msg[0]
        self.Nonce = msg[1]
        self.Version = msg[2]
            
    def __str__(self) -> str:
        randPubKey = f"RandomPubkey:\t\t{bytes_to_hex(self.RandomPubkey)}"
        nonce = f"Nonce:\t\t{bytes_to_hex(self.Nonce)}"
        version = f"Version:\t\t{bytes_to_hex(self.Version)}"
        return f"AuthRespV4:\n  {randPubKey}\n  {nonce}\n  {version}"
    
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
    def __init__(self, pubk: bytes, aes_secret: bytes, mac_secret: bytes) -> None:
        self.remotePubk = pubk # remote-static-pubk
        self.aes = aes_secret
        self.mac = mac_secret
        self.hashalgo = keccak
        self.egressMac = keccak.new(digest_bits=256)
        self.ingressMac = keccak.new(digest_bits=256)
        
    
class HandshakeState:
    """
    HandshakeState holds all of the valuable information during an active
    handshake between two nodes. After a successful handshake, the two nodes
    pull out all of the secrets that they shared via the handshake
    """
    def __init__(self, started: bool, init: bool, privK: bytes) -> None:
        self.started = started # whether the Handshake has initiated yet or not
        self.initiator = init
        self.privk = privK     # static private key (non-changing)
        self.remotePubk = None # static remote public key (non-changing)
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


# RLPx Frame Relates Types / Classes
#######################################################################################

class SessionState:
    """Contains the session keys"""
    def __init__(self) -> None:
        self.ctr = Counter
        self.cipher = ECIES_AES128_SHA256.Cipher
        self.enc = None
        self.dec = None
        self.egressMac = keccak.new(digest_bits=256)
        self.ingressMac = keccak.new(digest_bits=256)
        
class PeerConnection:
    """
    An RLPx network connection to an <other> node
    
    Before sending messages, a handshake must be performed
    """
    def __init__(self, privK: bytes, remotePubK: bytes, initiator: bool, ipaddr: str = None) -> None:
        self.ipaddr = ipaddr
        self.remotePubK = remotePubK # static public key of the peer
        self.hshakeCompleted = False
        self.handshakeState = HandshakeState(False, initiator, privK)
        self.session = SessionState()
        
