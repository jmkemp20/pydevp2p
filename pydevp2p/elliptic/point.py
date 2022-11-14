from pydevp2p.elliptic.jacobian import jacobian_add, jacobian_multiply, to_jacobian
from pydevp2p.elliptic.types import secp256k1

def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def from_jacobian(p: tuple[int, int, int]) -> tuple[int, int]:
    z = inv(p[2], secp256k1.P)
    return ((p[0] * z**2) % secp256k1.P, (p[1] * z**3) % secp256k1.P)

def fast_multiply(a: tuple[int, int], n: int):
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))

def fast_add(a: tuple[int, int], b: tuple[int, int]):
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))