from pydevp2p.crypto.secp256k1 import signature_to_pubk
from pydevp2p.crypto.utils import verifyHash
from pydevp2p.discover.v4wire.msg import Header, Packet, decodeMessageByType
from pydevp2p.utils import bytes_to_hex, bytes_to_int, framectx

# UDP packet constants.
MAC_SIZE = 256 // 8  # 32
SIG_SIZE = 520 // 8  # 65
HEAD_SIZE = MAC_SIZE + SIG_SIZE  # 97


def recoverNodeKey(msg: bytes, sig: bytes) -> bytes | None:
    # p2p/discover/v4wire/v4wire.go, crypto/signature_cgo.go
    pkey = signature_to_pubk(msg, sig)
    if pkey is None:
        print(f"{framectx()} recoverNodeKey pkey is None")
        return None
    return pkey


def decodeDiscv4(input: bytes) -> tuple[Header, Packet | None] | None:
    if len(input) < HEAD_SIZE + 1:
        # This will throw most likely if the discovery packet is discv5
        # print(f"{framectx()} decodeDiscv4(input): Err Packet Too Small")
        return

    header: Header = None
    try:
        hash, sig, sigdata = input[:MAC_SIZE], input[MAC_SIZE:HEAD_SIZE], input[HEAD_SIZE:]
        packetType = sigdata[:1]
        if 6 < bytes_to_int(packetType) < 1:
            print(
                f"{framectx()} decodeDiscv4(input) Err Invalid Packet Type {bytes_to_int(packetType)}")
            return None
        header = Header(hash, sig, packetType)
    except BaseException as e:
        # This will throw most likely if the discovery packet is discv5
        # print(f"{framectx()} decodeDiscv4(input) Err {e}")
        return None

    if not verifyHash(hash, input[MAC_SIZE:]):
        print(f"{framectx()} decodeDiscv4(input): Err Unable To Verify Hash")
        return None

    # Wow this is performance intensive
    fromKey = recoverNodeKey(sigdata, sig)
    if fromKey is None:
        return None

    print("fromKey", bytes_to_hex(fromKey))

    return header, decodeMessageByType(header.type, sigdata[1:])
