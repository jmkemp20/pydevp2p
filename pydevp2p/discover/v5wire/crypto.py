from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF

from pydevp2p.discover.datatypes import Enode
from pydevp2p.discover.v5wire.session import Session
from pydevp2p.elliptic.curve import decode_pubkey, encode_pubkey, multiply
from pydevp2p.utils import bytes_to_int, int_to_bytes


# geth/p2p/discover/v5wire/crypto.go
# Encryption/authentication parameters.
aesKeySize = 16
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
    return encode_pubkey(e, "bin_electrum")


def idNonceHash(hash, challenge: bytes, ephkey: bytes, destID: bytes) -> bytes:
    # idNonceHash computes the ID signature hash used in the handshake.
    return


def makeIDSignature(hash, privk: bytes, challenge: bytes, ephkey: bytes, destID: bytes) -> bytes | None:
    # makeIDSignature creates the ID nonce signature.
    return


def verifyIDSignature(hash, sig: bytes, n: Enode, challenge: bytes, ephkey: bytes, destID: bytes) -> bool:
    # verifyIDSignature checks that signature over idnonce was made by the given node.
    return True


def deriveKeys(hash, privk: bytes, pubk: bytes, n1: bytes, n2: bytes, challenge: bytes) -> Session:
    # deriveKeys creates the session keys.
    text = "discovery v5 key agreement".encode('utf-8')
    info = text + n1 + n2
    if len(info) != len(text) + len(n1) + len(n2):
        print("deriveKeys(hash, privk, pubk, n1, n2, challenge) Err Invalid Info Len")
        return None

    eph = ecdh(pubk, privk)
    if eph is None:
        print("deriveKeys(hash, privk, pubk, n1, n2, challenge) Err Unable to Generate Shared Secret")
        return None

    writeKey, readKey = HKDF(
        master=eph, key_len=16, salt=challenge, hashmod=hash, num_keys=2, context=info)
    return Session(writeKey, readKey, 0)


def ecdh(pubk: bytes, privk: bytes) -> bytes:
    # ecdh creates a shared secret.
    eph_key = multiply(pubk, privk)
    shr_key = decode_pubkey(eph_key)
    first = bytes_to_int(b'\x02') | ((shr_key[1] >> 0) & 1)

    return int_to_bytes(first) + int_to_bytes(shr_key[0])


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
    if len(nonce) != gcmNonceSize:
        print(
            f"decryptGCM(key, nonce, ct, authData) Err Invalid Nonce Size: Exptected {gcmNonceSize}, Got {len(nonce)}")
        return None

    cipher = AES.new(key, mode=AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt(ct)

    return pt
