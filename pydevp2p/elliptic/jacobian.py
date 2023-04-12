from pydevp2p.elliptic.types import secp256k1

# Jacobian coordinates are a way to represent points on an elliptic curve
# .. This is a more efficient way to perform operations on the curve
# .. This file contains functions to convert between affine and jacobian coordinates
# .. and to perform operations on points in jacobian coordinates
# .. Original implementation by:
# .... https://github.com/primal100/pybitcointools/blob/master/cryptos/main.py


def to_jacobian(p: tuple[int, int]) -> tuple[int, int, int]:
    o = (p[0], p[1], 1)
    return o


def jacobian_double(p: tuple[int, int, int]) -> tuple[int, int, int]:
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % secp256k1.P
    S = (4 * p[0] * ysq) % secp256k1.P
    M = (3 * p[0] ** 2 + secp256k1.A * p[2] ** 4) % secp256k1.P
    nx = (M**2 - 2 * S) % secp256k1.P
    ny = (M * (S - nx) - 8 * ysq ** 2) % secp256k1.P
    nz = (2 * p[1] * p[2]) % secp256k1.P
    return (nx, ny, nz)


def jacobian_add(p: tuple[int, int, int], q: tuple[int, int, int]) -> tuple[int, int, int]:
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % secp256k1.P
    U2 = (q[0] * p[2] ** 2) % secp256k1.P
    S1 = (p[1] * q[2] ** 3) % secp256k1.P
    S2 = (q[1] * p[2] ** 3) % secp256k1.P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % secp256k1.P
    H3 = (H * H2) % secp256k1.P
    U1H2 = (U1 * H2) % secp256k1.P
    nx = (R ** 2 - H3 - 2 * U1H2) % secp256k1.P
    ny = (R * (U1H2 - nx) - S1 * H3) % secp256k1.P
    nz = (H * p[2] * q[2]) % secp256k1.P
    return (nx, ny, nz)


def jacobian_multiply(a: tuple[int, int, int], n: int) -> tuple[int, int, int]:
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= secp256k1.N:
        return jacobian_multiply(a, n % secp256k1.N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n//2))
    if (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n//2)), a)
