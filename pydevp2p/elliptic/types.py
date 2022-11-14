import copy
from pydevp2p.crypto.params import ECIES_Params
from pydevp2p.utils import bytes_to_hex

# Base Elliptic Curve class with (secp256k1) defaults
class EllipticCurve:
    P = int
    N = int
    A = int
    B = int
    Gx = int
    Gy = int
    size = int # bits
    G = (int, int)
    

# Elliptic curve parameters (secp256k1)
class secp256k1(EllipticCurve):
    P = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    N = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    A = 0
    B = 7
    H = 1
    Gx = int("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    Gy = int("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    size = 256 # bits
    G = (Gx, Gy)
    
# The base Public Key class
class PublicKey:
    def __init__(self, pub: bytes, curve: EllipticCurve, params: ECIES_Params) -> None:
        self.Key = pub
        self.Curve = curve
        self.Params = params
        
    def toHex(self) -> str:
        return bytes_to_hex(self.Key)
    
class PrivateKey:    
    def __init__(self, priv: bytes, pub: PublicKey) -> None:
        self.PublicKey = copy.copy(pub)
        self.Key = priv
        
    def toHex(self) -> str:
        return bytes_to_hex(self.Key)

    
    