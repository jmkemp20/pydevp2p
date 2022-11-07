
from pydevp2p.crypto.secp256k1 import signature_to_pubk
from pydevp2p.crypto.utils import verifyHash
from rlp.codec import decode

macSize = 32
sigSize = 65
headSize = macSize + sigSize

def recoverNodeKey(msg: bytes, sig: bytes) -> bytes:
    # p2p/discover/v4wire/v4wire.go, crypto/signature_cgo.go
    pkey = signature_to_pubk(msg, sig)
    if pkey is None:
        print("recoverNodeKey pkey is None")
        return None
    return pkey


def decodeDiscv4(input: bytes):
    if len(input) < headSize + 1:
        print("decodeDiscv4(input): Err Packet Too Small")
        return
    hash, sig, sigdata = input[:macSize], input[macSize:headSize], input[headSize:]
    if not verifyHash(hash, input[macSize:]):
        print("decodeDiscv4(input): Err Unable To Verify Hash")
        return
    fromKey = recoverNodeKey(sigdata, sig)
    dec = decode(sigdata[1:])
    # print(dec)
    return fromKey
    # TODO RLP decoding by packet type