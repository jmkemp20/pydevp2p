# Contains crypto utility functions and constants

def keccak256Hash(input: bytes):
    from Crypto.Hash import keccak
    keccak_hash = keccak.new(digest_bits = 256)
    keccak_hash.update(input)
    return keccak_hash.digest()

def verifyHash(fromHash, input: bytes):
    outHash = keccak256Hash(input)
    return outHash == fromHash

def xor(a: bytes, b: bytes) -> bytes:
    xor = b'' * len(a)
    for i in range(len(a)):
        xor[i] = a[i] ^ b[i]
    return xor