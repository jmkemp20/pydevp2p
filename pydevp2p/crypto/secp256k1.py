from pydevp2p.crypto.utils import keccak256Hash
from pydevp2p.elliptic.types import secp256k1
from pydevp2p.elliptic import curve

# Cryptography functions related to the secp256k1 curve
# All functions, validations, etc are specific to the curve secp256k1

def privtopub(raw_privkey) -> bytes:
    raw_pubkey = curve.encode_pubkey(curve.privtopub(raw_privkey), 'bin_electrum')
    assert len(raw_pubkey) == 64
    return raw_pubkey

def isValidFieldElement(num: int) -> bool:
    return 0 < num and num < secp256k1.P

def nmod(a: int, b: int = secp256k1.P) -> int:
    res = a % b
    return res if res >= 0 else b + res

def weistress(x: int) -> int:
    a = secp256k1.A
    b = secp256k1.B
    x2 = nmod(x * x)
    x3 = nmod(x2 * x)
    return nmod(x3 + a * x + b)

def assertValidity(x: int, y: int) -> bool:
    """Asserts whether two coordinates x, y are valid 

    Args:
        x (int): _description_
        y (int): _description_

    Returns:
        bool: _description_
    """
    if not isValidFieldElement(x) or not isValidFieldElement(y):
        print("assertValidity(x, y) x,y is Not on the elliptic curve")
        return False
    left = nmod(y * y)
    right = weistress(x)
    if nmod(left - right) != 0:
        print("assertValidity(x, y) x,y is Not on the elliptic curve")
        return False
    return True
    
def comparePoints(x: int, y: int) -> int:
    """comparePoints compares points x and y

    Args:
        x (int): Point on curve
        y (int): Point on curve

    Returns:
        int: -1 if x <  y OR 0 if x == y OR +1 if x >  y
    """
    # NOTE this algorithm differs significantly from GO source math/big/int.go and nat.go
    if x == y:
        return 0
    elif x < y:
        return -1
    return 1

# ECDSA: Elliptic Curve Signatures
# https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages

def verify_signature(sig: bytes):
    # crypto/secp256k1/secp256.go
    if len(sig) != 65:
        print(f"checkSignature(sig) Err Invalid Signature Len: {len(sig)} != 65")
        return False
    if sig[64] >= 4:
        print(f"checkSignature(sig) Err Invalid Recovery ID: {sig[64]} >= 4")
        return False
    return True

def recover_pubk(hash: bytes, sig: bytes) -> bytes:
    # TODO - Remove this dependency
    from eth_keys import KeyAPI
    test_sig = KeyAPI.Signature(sig)
    pkey = test_sig.recover_public_key_from_msg_hash(hash)
    if not pkey.verify_msg_hash(hash, test_sig):
        print("recover_pubk(hash, sig): Err Unable To Verify Msg")
        return None
    return pkey.to_bytes()

def signature_to_pubk(msg: bytes, sig: bytes) -> bytes | None:
    """Public key recovery from the ECDSA signature
    https://www.secg.org/sec1-v2.pdf
        
    Allows for any party to recover the public key of the sender via the ECDSA
    signature, and validating and verifying with the msg itself that the signature
    was created from
    
    Ethereum block chain uses extended signatures { r, s, v } for signed transactions
    on the chain to save storage and bandwidth

    Args:
        msg (bytes): The raw msg data that was signed
        sig (bytes): The ECDSA signature calculated from the msg

    Returns:
        bytes: The raw public key of the node that signed the msg
    """
    # crypto/secp256k1/secp256.go
    return recover_pubk(keccak256Hash(msg), sig)

def ecdsa_sign(digestHash: bytes, privK: bytes) -> bytes:
    """_summary_

    Args:
        digestHash (bytes): _description_
        privK (bytes): _description_

    Returns:
        bytes: _description_
    """
    pass

def unmarshal(data: bytes) -> bytes | None:
    """Unmarshal converts a point, serialized by Marshal, into an x, y pair. It is
    an error if the point is not in uncompressed form, is not on the curve, or is
    the point at infinity. On error, x = None.
    
    There really isn't much to do here, other than validate the public key 
    in the data from the incomming message

    Args:
        data (bytes): The raw uncompressed public key (in the clear)

    Returns:
        bytes | None: The raw public key, cleansed and verified otherwise None
    """
    # The curve "could" be on {p224, p256, p384, p521}
    # .. NOTE for now we are using the standard secp256k1: ethcrypto.S256(): ECIES_AES128_SHA256
    byteLen = int((secp256k1.size + 7) / 8)
    
    data = b'\x04' + data if len(data) == 64 else data
    
    if len(data) != 1 + 2 * byteLen:
        print(f"unmarshal(data) Err len(data) != 1 * 2 * byteLen, {len(data)} != {1 + 2 * byteLen}")
        return None
    
    if data[0] != 4: 
        print(f"unmarshal(data) Err data[0] != 4, {data[0]} != 4")
        return None
    
    x, y = curve.decode_pubkey(data)
    
    if comparePoints(x, secp256k1.P) >= 0 or comparePoints(y, secp256k1.P) >=0:
        print(f"unmarshal(data) Err comparePoints(x | y, secp256k1.P)")
        return None
    
    if not assertValidity(x, y):
        print(f"unmarshal(data) Err assertValidity(x, y)")
        return None
    
    return curve.encode_pubkey((x,y), "bin_electrum")