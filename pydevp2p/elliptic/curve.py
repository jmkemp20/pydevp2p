from pydevp2p.crypto.params import ECIES_AES128_SHA256
from pydevp2p.elliptic.jacobian import jacobian_add, jacobian_multiply, to_jacobian
from pydevp2p.elliptic.types import EllipticCurve, PrivateKey, PublicKey, secp256k1
from pydevp2p.elliptic.point import fast_multiply, from_jacobian, inv
from pydevp2p.utils import bytes_to_int, int_to_bytes
from pydevp2p.elliptic.utils import *
# Holds the lower level elliptic curve point calculations
# .. NOTE this is mostly applicable only to the secp256k1 curve


def isinf(p):
    return p[0] == 0 and p[1] == 0


def get_pubkey_format(pub) -> str:
    two = 2
    three = 3
    four = 4

    if isinstance(pub, (tuple, list)):
        return 'decimal'
    elif len(pub) == 65 and pub[0] == four:
        return 'bin'
    elif len(pub) == 130 and pub[0:2] == '04':
        return 'hex'
    elif len(pub) == 33 and pub[0] in [two, three]:
        return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in ['02', '03']:
        return 'hex_compressed'
    elif len(pub) == 64:
        return 'bin_electrum'
    elif len(pub) == 128:
        return 'hex_electrum'
    else:
        raise Exception("Pubkey not in recognized format")


def get_privkey_format(priv: int | str | bytes) -> str | None:
    if isinstance(priv, int):
        return 'decimal'
    elif len(priv) == 32:
        return 'bin'
    elif len(priv) == 33:
        return 'bin_compressed'
    elif len(priv) == 64:
        return 'hex'
    elif len(priv) == 66:
        return 'hex_compressed'
    else:
        return None


def decode_pubkey(pub, formt=None) -> tuple[int, int]:
    A = secp256k1.A
    B = secp256k1.B
    P = secp256k1.P
    if not formt:
        formt = get_pubkey_format(pub)
    if formt == 'decimal':
        return pub
    elif formt == 'bin':
        return (decode(pub[1:33], 256), decode(pub[33:65], 256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33], 256)
        beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))
        y = (P-beta) if ((beta + from_byte_to_int(pub[0])) % 2) else beta
        return (x, y)
    elif formt == 'hex':
        return (decode(pub[2:66], 16), decode(pub[66:130], 16))
    elif formt == 'hex_compressed':
        return decode_pubkey(bytes.fromhex(pub), 'bin_compressed')
    elif formt == 'bin_electrum':
        return (decode(pub[:32], 256), decode(pub[32:64], 256))
    elif formt == 'hex_electrum':
        return (decode(pub[:64], 16), decode(pub[64:128], 16))
    else:
        return None


def decode_privkey(priv, formt=None):
    if not formt:
        formt = get_privkey_format(priv)
    if formt == 'decimal':
        return priv
    elif formt == 'bin':
        return decode(priv, 256)
    elif formt == 'bin_compressed':
        return decode(priv[:32], 256)
    elif formt == 'hex':
        return decode(priv, 16)
    elif formt == 'hex_compressed':
        return decode(priv[:64], 16)
    else:
        return None


def encode_pubkey(pub, formt) -> bytes | str:
    if not isinstance(pub, (tuple, list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal':
        return pub
    elif formt == 'bin':
        return b'\x04' + encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'bin_compressed':
        return from_int_to_byte(2+(pub[1] % 2)) + encode(pub[0], 256, 32)
    elif formt == 'hex':
        return '04' + encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    elif formt == 'hex_compressed':
        return '0'+str(2+(pub[1] % 2)) + encode(pub[0], 16, 64)
    elif formt == 'bin_electrum':
        return encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'hex_electrum':
        return encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    else:
        return None


def encode_privkey(priv, formt, vbyte=0):
    if not isinstance(priv, int):
        return encode_privkey(decode_privkey(priv), formt, vbyte)
    if formt == 'decimal':
        return priv
    elif formt == 'bin':
        return encode(priv, 256, 32)
    elif formt == 'bin_compressed':
        return encode(priv, 256, 32)+b'\x01'
    elif formt == 'hex':
        return encode(priv, 16, 64)
    elif formt == 'hex_compressed':
        return encode(priv, 16, 64)+'01'
    else:
        return None


def multiply(pubkey, privkey):
    B = secp256k1.B
    P = secp256k1.P
    f1, f2 = get_pubkey_format(pubkey), get_privkey_format(privkey)
    pubkey, privkey = decode_pubkey(pubkey, f1), decode_privkey(privkey, f2)
    # http://safecurves.cr.yp.to/twist.html
    if not isinf(pubkey) and (pubkey[0]**3+B-pubkey[1]*pubkey[1]) % P != 0:
        raise Exception("Point not on curve")
    return encode_pubkey(fast_multiply(pubkey, privkey), f1)


def privkey_to_pubkey(privkey):
    N = secp256k1.N
    G = secp256k1.G
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey, f)
    if not privkey or privkey >= N:
        raise Exception("Invalid privkey")
    if f in ['bin', 'bin_compressed', 'hex', 'hex_compressed', 'decimal']:
        return encode_pubkey(fast_multiply(G, privkey), f)
    else:
        return encode_pubkey(fast_multiply(G, privkey), f.replace('wif', 'hex'))


def generate_key(rand: bytes, curve: EllipticCurve = secp256k1) -> tuple[bytes, bytes] | None:
    """GenerateKey returns a public/private key pair. The private key is
    generated using the given rand, which must return random data.

    Args:
        rand (bytes): The given random number data to generate the G offset
        curve (EllipticCurve, optional): The elliptic curve class object. Defaults to secp256k1.

    Returns:
        tuple[bytes, bytes] | None: (privK, pubK) or if there is an error None
    """
    pass


def create_private_key(key: int | str | bytes) -> PrivateKey:
    privk: bytes | None = None
    if isinstance(key, str):
        privk = bytes.fromhex(key)
    elif isinstance(key, int):
        privk = int_to_bytes(key)
    elif isinstance(key, bytes):
        privk = key
    else:
        raise Exception("Invalid Private Key Format")
    pubk = privkey_to_pubkey(privk)
    if not isinstance(pubk, bytes):
        raise Exception("Public Key not in correct format")
    pub = PublicKey(pubk, secp256k1, ECIES_AES128_SHA256)
    return PrivateKey(privk, pub)


def decode_sig(sig: bytes) -> tuple[int, int, int]:
    r = bytes_to_int(sig[0:32])
    s = bytes_to_int(sig[32:64])
    v = ord(sig[64:65])
    return (r, s, v)


def ecdsa_raw_recover(msghash: bytes, rsv: tuple[int, int, int]):
    # https://www.secg.org/sec1-v2.pdf page 47-48
    # https://gist.github.com/nlitsme/dda36eeef541de37d996
    N = secp256k1.N
    A = secp256k1.A
    B = secp256k1.B
    H = secp256k1.H
    P = secp256k1.P
    G = secp256k1.G
    r, s, v = rsv

    x = r

    ysqaure = (x**3 + A * x + B)
    beta = pow(ysqaure, (P+1)//4, P)
    y = beta if beta % 2 == v else -beta
    R = (x, y)

    m = bytes_to_int(msghash)
    # R * s
    Rs = jacobian_multiply(to_jacobian(R), s)
    # G * m // r
    Gz = jacobian_multiply(to_jacobian(G), (N - m) % N)

    # (R * s - G * m)
    Qr = jacobian_add(Rs, Gz)
    Q = jacobian_multiply(Qr, inv(r, N))
    Q = from_jacobian(Q)

    return encode_pubkey(Q, "bin_electrum")
    # return False
