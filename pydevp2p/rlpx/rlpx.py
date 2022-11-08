
from pydevp2p.crypto.utils import keccak256Hash, xor
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4, HandshakeState, Secrets
from pydevp2p.utils import bytes_to_int
from pydevp2p.crypto.ecies import decrypt, generate_shared_secret
from rlp.codec import decode

# Handshake and secret sharing functions

def is_auth_init_msg(msg: list[bytes] | AuthMsgV4 | AuthRespV4) -> bool:
    parse = parse_auth_type(msg) if isinstance(msg, list) else msg
    return True if isinstance(parse, AuthMsgV4) else False

def is_auth_resp_msg(msg: list[bytes] | AuthMsgV4 | AuthRespV4) -> bool:
    parse = parse_auth_type(msg) if isinstance(msg, list) else msg
    return True if isinstance(parse, AuthRespV4) else False
    
def parse_auth_type(authmsg: list[bytes]) -> AuthMsgV4 | AuthRespV4 | None:
    if AuthMsgV4.validate(authmsg):
        return AuthMsgV4(authmsg)
    elif AuthRespV4.validate(authmsg):
        return AuthRespV4(authmsg)
    return None

def get_secrets(h: HandshakeState, authData: bytes, AuthRespData: bytes):
    """Called after a successful handshake is completed
    
    Extracts all the information from the shared handshake values
    
    What is known before this function call: (all what is in HandshakeState)
        [static keys] static-privk (privk), static-remote-pubk (remotePubk)
        static-shared-secret = S = Px = generate_shared_secret( static-remotePubk, static-privk )
        initiator-nonce (initNonce), resp-nonce (respNonce)
        [ecdh random keys] ephemeral-privk (randomPrivk), ephemeral-remote-pubk (remoteRandomPubk)
    What is gained after this function call:
        ephemeral-key = S = Px = generate_shared_secret( ephemeral-remote-pubk, emphemeral-privk )
        shared-secret = keccak256hash( ephemeral-key, keccak256hash( respNonce, initNonce ) )
        aes-secret = keccak256hash( ephemeral-secret, shared-secret )
        mac-secret = keccak256hash( ephemeral-secret, aes-secret )

    Args:
        h (HandshakeState): static priv/pubk, ephemeral priv/pubk, nonce values, etc...
        authData (bytes): _description_
        AuthRespData (bytes): _description_
    """
    # geth p2p/rlpx/rlpx.go Line # 473

    # 1) Creates the ephemeral-key (ecdheSecret) using:
    # .... The ephemeral-privkey (randomPrivKey) and remote-ephemeral-pubk (remoteRandomPub)
    ephemeral_key = generate_shared_secret(h.remoteRandomPubk, h.randomPrivk)
    if ephemeral_key is None:
        return None
    
    # 2) Derives the shared-secret from the ephermeral key agreement
    # .... shared-secret = keccak256hash( ephemeral-key, keccak256hash( respNonce, initNonce ) )
    shared_secret = keccak256Hash(ephemeral_key, keccak256Hash(h.respNonce, h.initNonce))
    
    # 3) Calculate the aes-secret using the hash of both the ephemeral-key and shared-secret
    # .... aes-secret = keccak256hash( ephemeral-secret, shared-secret )
    aes_secret = keccak256Hash(ephemeral_key, shared_secret)
    
    # 4) Calculate the mac-secret with the hash of both the ephemeral-key and aes-key
    # .... mac-secret = keccak256hash( ephemeral-secret, aes-secret )
    mac_secret = keccak256Hash(ephemeral_key, aes_secret)
    
    # 5) Lastly, calculate the Egress and Ingress MACs (depending on if initiator or not)
    s = Secrets(h.remotePubk, aes_secret, mac_secret)
    # mac1 = keccak.update( xor( mac_secret, respNonce ) ).update( authData )
    mac1 = s.hashalgo.new(digest_bits=256)
    mac1.update(xor(mac_secret, h.respNonce))
    mac1.update(authData)
    # mac2 = keccak.update( xor( mac_secret, initNonce ) ).update( AuthRespData )
    mac2 = s.hashalgo.new(digest_bits=256)
    mac2.update(xor(mac_secret, h.initNonce))
    if h.initiator:
        s.egressMac, s.ingressMac = mac1, mac2
    else:
        s.egressMac, s.ingressMac = mac2, mac1

    return s

def read_handshake_msg(privK: bytes, msg: bytes) -> AuthMsgV4 | AuthRespV4 | None:
    """readMsg reads an encrypted handshake message, decoding it into msg.
    The decoded output is either an:
    .. Auth Msg V4 (from the initiator)
    .. Auth Resp V4 (from the recipient)

    Args:
        privK (bytes): _description_
        msg (bytes): _description_
    """
    prefix = msg[:2]
    size = bytes_to_int(prefix)
    data = msg[2:]
    if len(data) != size:
        print("readMsg(privK, msg) Err msg not the right length")
        return
    
    # Decrypt the ciphertext data, with an empty s1, 2 bytes prefix for s1 and the private key
    # .. decrypt: (c: bytes, s1: bytes, s2: bytes, privK: bytes) -> (bytes | None)
    m = decrypt(data, "".encode(), prefix, privK)
    if m is None:
        print("readMsg(privK, msg) Err Unable to decrypt msg")
        return
    
    # Decode the decrypted message m utilizing the RLP encoding schema    
    dec = None
    try:
        dec = decode(m, strict=False)
    except BaseException as e:
        print(f"decode(m, strict=False) readMsg(privK, msg) {e}")
        return
    
    # Parse the decoded RLP msgs into either an Init Auth Msg or Auth Resp Msg
    # .. parse_auth_type: (authmsg: list[bytes]) -> (AuthMsgV4 | AuthRespV4 | None)
    auth = parse_auth_type(dec)
    if auth is None:
        print(f"parse_auth_type(dec) readMsg(privK, msg) {e}")
        return
        
    return auth


# RLPx Frame Decryption Functions
#######################################################################################