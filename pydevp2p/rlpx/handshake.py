from Crypto.Hash import keccak
from rlp.codec import decode

from pydevp2p.crypto.ecies import decrypt, generate_shared_secret
from pydevp2p.crypto.secp256k1 import recover_pubk, unmarshal
from pydevp2p.crypto.utils import keccak256Hash, xor
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4
from pydevp2p.utils import bytes_to_hex, bytes_to_int

# Handshake Relates Types / Classes


class Secrets:
    """
    Secrets represents the connection secrets which are negotiated during the handshake.
    """

    def __init__(self, pubk: bytes, ephemeral_key: bytes, shared_secret: bytes, aes_secret: bytes, mac_secret: bytes) -> None:
        self.remotePubk = pubk  # remote-static-pubk
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
        self.remotePubk = remotePubk  # static remote public key (non-changing)
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
            print(
                "HandshakeState handleAuthMsg(msg, privk) Err Static Shared Secret None")
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
            print(
                "HandshakeState secrets(auth, authResp) Error randomPrivk or remoteRandomPubk is None")
            return None

        if self.initNonce is None or self.respNonce is None:
            print(
                "HandshakeState secrets(auth, authResp) Error initNonce or respNonce is None")
            return None

        # 1) Creates the ephemeral-key (ecdheSecret) using:
        # .... The ephemeral-privkey (randomPrivKey) and remote-ephemeral-pubk (remoteRandomPub)
        ephemeral_key = generate_shared_secret(
            self.remoteRandomPubk, self.randomPrivk)
        if ephemeral_key is None:
            return None

        # 2) Derives the shared-secret from the ephermeral key agreement
        # .... shared-secret = keccak256hash( ephemeral-key, keccak256hash( respNonce, initNonce ) )
        shared_secret = keccak256Hash(
            ephemeral_key + keccak256Hash(self.respNonce + self.initNonce))
        # 3) Calculate the aes-secret using the hash of both the ephemeral-key and shared-secret
        # .... aes-secret = keccak256hash( ephemeral-secret, shared-secret )
        aes_secret = keccak256Hash(ephemeral_key + shared_secret)

        # 4) Calculate the mac-secret with the hash of both the ephemeral-key and aes-key
        # .... mac-secret = keccak256hash( ephemeral-secret, aes-secret )
        mac_secret = keccak256Hash(ephemeral_key + aes_secret)

        # 5) Lastly, calculate the Egress and Ingress MACs (depending on if initiator or not)
        s = Secrets(self.remotePubk, ephemeral_key,
                    shared_secret, aes_secret, mac_secret)
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


def parse_auth_type(authmsg: list[bytes]) -> AuthMsgV4 | AuthRespV4 | None:
    if AuthMsgV4.validate(authmsg):
        return AuthMsgV4(authmsg)
    elif AuthRespV4.validate(authmsg):
        return AuthRespV4(authmsg)
    return None


def read_handshake_msg(privK: bytes, msg: bytes) -> tuple[AuthMsgV4 | AuthRespV4 | None, bytes] | None:
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
        print(f"parse_auth_type(dec) readMsg(privK, msg) Err Parsed Auth is None")
        return

    return (auth, msg[:len(prefix)+len(data)])
