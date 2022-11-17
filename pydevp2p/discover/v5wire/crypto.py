from pydevp2p.discover.datatypes import Enode
from pydevp2p.discover.v5wire.session import Session


# geth/p2p/discover/v5wire/crypto.go
# Encryption/authentication parameters.
aesKeySize   = 16
gcmNonceSize = 12

# Stores the discv5 specific and tailored cryptographic functionality

def encodePubk(pubk: bytes) -> bytes:
    # EncodePubkey encodes (compresses) a public key.
    return

def decodePubk(e: bytes) -> bytes | None:
    # DecodePubkey decodes a public key in compressed format.
    # .. NOTE using the secp256k1 curve
    if len(e) != 33:
        print(f"decodePubk(e) Err Invalid len, Expected 33 Got {len(e)}")
        return None
    
    # TODO decompress the compressed pubk e here
    # dec = decompressPubk(e)
    return e

def idNonceHash(hash, challenge: bytes, ephkey: bytes, destID: bytes) -> bytes:
    # idNonceHash computes the ID signature hash used in the handshake.
    return

def makeIDSignature(hash, privk: bytes, challenge: bytes, ephkey: bytes, destID: bytes) -> bytes | None:
    # makeIDSignature creates the ID nonce signature.
    return

def verifyIDSignature(hash, sig: bytes, n: Enode, challenge: bytes, ephkey: bytes, destID: bytes) -> bool:
    # verifyIDSignature checks that signature over idnonce was made by the given node.
    return

def deriveKeys(hash, privk: bytes, pubk: bytes, n1: bytes, n2: bytes, challenge: bytes) -> Session:
    # deriveKeys creates the session keys.
    return

def ecdh(privk: bytes, pubk: bytes) -> bytes:
    # ecdh creates a shared secret.
    return

def encryptGCM(dest: bytes, key: bytes, nonce: bytes, plaintext: bytes, authData: bytes) -> bytes | None:
    """encryptGCM encrypts pt using AES-GCM with the given key and nonce.
    The ciphertext is appended to dest, which must not overlap with plaintext.
    The resulting ciphertext is 16 bytes longer than plaintext because it contains
    an authentication tag.

    Args:
        dest (bytes): _description_
        key (bytes): _description_
        nonce (bytes): _description_
        plaintext (bytes): _description_
        authData (bytes): _description_

    Returns:
        bytes | None: _description_
    """
    return

def decryptGCM(key: bytes, nonce: bytes, ct: bytes, authData: bytes) -> bytes | None:
    """decryptGCM decrypts ct using AES-GCM with the given key and nonce.

    Args:
        key (bytes): _description_
        nonce (bytes): _description_
        ct (bytes): _description_
        authData (bytes): _description_

    Returns:
        bytes | None: _description_
    """
    return
 