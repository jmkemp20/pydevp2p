from Crypto.Hash import HMAC
from Crypto.Util import Counter

from pydevp2p.utils import bytes_to_hex, bytes_to_int, hex_to_bytes, int_to_bytes
from pydevp2p.crypto.secp256k1 import unmarshal
from pydevp2p.crypto.params import ECIES_Params, ECIES_AES128_SHA256
from pydevp2p.elliptic.types import secp256k1
from pydevp2p.elliptic.curve import multiply, decode_pubkey

# ECDH Key Exchange
# https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange


def generate_ephemeral_key(rand: bytes) -> bytes:
    """Generate a temporary elliptic curve public / private keypair.

    Public key (R) generated via R = r * G
    Only used right before encryption, to generate a temporary public/private

    Args:
        rand (bytes): Random data to support key generation

    Returns:
        bytes: Private Key pair in support of encryption
    """
    # TODO - Primarily takes place prior to encryption of a message
    pass


def generate_shared_secret(pub: bytes, priv: bytes) -> bytes | None:
    """ECDH key agreement method used to establish secret keys for encryption.

    Encryption: such that S = Px where (Px, Py) = r * pubK
    Decryption: such that S = Px where (Px, Py) = privK * R
    where r and privK is (priv) and pubK and R is (pub)

    Using myPublicKey * theirPrivateKey = theirPublicKey * myPrivateKey = secret
    Where the pubk is from the other party

    Args:
        pub (bytes): public key of other node
        priv (bytes): private key of self node

    Returns:
        bytes | None: S if able to generate shared secret otherwise None
    """
    # NOTE this is different than crypto/ecies/ecies.go
    try:
        eph_key = multiply(pub, priv)
        shr_key = decode_pubkey(eph_key)[0]
        return int_to_bytes(shr_key)
    except Exception as e:
        print(f"generate_shared_key() {e}")
        return None


def concatKDF(hash, z: bytes, s1: bytes, kdlen: int, s2: bytes = None) -> bytes:
    """NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
    This extracts key-material from the shared-secret, specifically the 
    encryption-key and mac-key

    Args:
        hash (bool): The hash function to use
        z (bytes): The shared secret S
        s1 (bytes): Shared infromation to effect the hash (usually part of the msg)
        kdlen (int): 2 * the AES keylen

    Returns:
        bytes: The resulting concatenated encryption and MAC keys (Ke || Km)
    """
    k = b''
    counter = 1
    while len(k) < kdlen:
        counterbytes = counter.to_bytes(4, "big")
        hash = hash.new()
        hash.update(counterbytes)
        hash.update(z)
        hash.update(s1)
        if s2 is not None:
            hash.update(s2)
        k = k + hash.digest()
        counter += 1
    return k[:kdlen]


def derive_keys(params: ECIES_Params, z: bytes, s1: bytes) -> tuple[bytes, bytes]:
    """Derives key material for encryption and authentication from shared secret
    using concatKDF hashing function

    Args:
        hash (bool): Hash algorithm/function used
        z (bytes): The shared secret S
        s1 (bytes): Shared values, only effects KDF hash
        keylen (int): Len of hash digest size

    Returns:
        tuple[bytes, bytes]: (Ke, Km) Encryption Key, MAC Key
    """
    hash = params.Hash.new()
    keylen = params.KeyLen
    K = concatKDF(hash, z, s1, 2 * keylen)
    Ke = K[:keylen]
    Km = K[keylen:]
    hash = hash.new()
    hash.update(Km)
    Km = hash.digest()
    return Ke, Km


def message_tag(hashAlgo, Km: bytes, msg: bytes, shared: bytes, testMac: bytes) -> bytes | None:
    """messageTag computes the MAC of a message (called the tag) as per SEC 1, 3.5.

    Args:
        hashAlgo (ModuleType): The Hash Algorithm to be used in the HMAC digest
        Km (bytes): The derived MAC key
        msg (bytes): The msg to generate the MAC with
        shared (bytes): Shared information to effect MAC
        testMac (bytes): MAC to verify with generated MAC

    Returns:
        bytes: The computed message tag MAC
    """
    hmac = HMAC.new(Km, digestmod=hashAlgo)
    hmac.update(msg)
    hmac.update(shared)
    try:
        hmac.verify(testMac)
        return hmac.digest()
    except ValueError as e:
        print(f"message_tag(Km, msg, shared, testMac) Err {e}")
        return None


# Elliptic Curve Cryptography (ECC)
# https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
##############################################################################

def generateIV(blocksize: int, data: bytes) -> bytes:
    """_summary_

    Args:
        blocksize (int): _description_
        data (bytes): _description_

    Returns:
        bytes: _description_
    """
    # TODO - generateIV() Currently do not need this functionality
    pass


def sym_encrypt():
    # TODO - sym_encrypt() Currently do not need this functionality
    pass


def encrypt(pub: bytes, m: bytes, s1: bytes, s2: bytes) -> bytes:
    """Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1.

    s1 and s2 contain shared information that is not part of the resulting
    ciphertext. s1 is fed into key derivation, s2 is fed into the MAC. If the
    shared information parameters aren't being used, they should be nil.
    Args:
        pub (bytes): public key of the destination of message m
        m (bytes): plaintext message m to be encrypted
        s1 (bytes): shared information for key derivation
        s2 (bytes): shared information for MAC

    Returns:
        bytes: c ciphertext from encrypted plaintext message m
    """
    # TODO - encrypt() Currently do not need this functionality
    pass


def sym_decrypt(params: ECIES_Params, Ke: bytes, ct: bytes) -> bytes | None:
    """symDecrypt carries out CTR decryption using the block cipher specified in
    the parameters

    Args:
        params (ECIES_Params): The ECIES paramaters used for decryption/hashing
        Ke (bytes): The shared derived encryption key
        ct (bytes): The ciphertext to decrypt

    Returns:
        bytes | None: The decrypted ciphertext m or None if failed
    """
    iv = bytes_to_int(ct[:params.BlockSize])

    ctr = Counter.new(params.BlockSize * 8, initial_value=iv)
    decryptor = params.Cipher.new(Ke, params.Cipher.MODE_CTR, counter=ctr)
    plain_text = decryptor.decrypt(ct[params.BlockSize:])

    if len(ct) - params.BlockSize != len(plain_text):
        print(f"sym_decrypt(params, Ke, ct) Err Invalid Unable to Verify Decryption")
        return None

    return plain_text


def decrypt(c: bytes, s1: bytes, s2: bytes, privK: bytes) -> bytes | None:
    """Decrypt decrypts an ECIES ciphertext c

    s1 and s2 contain shared information that are not part of ciphertext
    c or the resulting message m. s1 is fed into key derivation, s2 is fed 
    into the MAC.

    Args:
        c (bytes):     ciphertext c to be decrypted - c = AES(k, iv, m)
        s1 (bytes):    shared information for key derivation
        s2 (bytes):    shared information for MAC
        privK (bytes): private key of self node

    Returns:
        bytes: m plaintext from decrypted ciphertext c
    """
    # First check the length of ciphertext c
    if len(c) == 0:
        print("decrypt(c, s1, s2) Err Invalid Message c, len(c) == 0")
        return None

    # Get the preferred hash algorithm via curve and shared key
    # .. NOTE for now, just using SHA.256
    # TODO This will become more dynamic in the future
    params: ECIES_Params = ECIES_AES128_SHA256

    rLen = 0
    hLen = params.Hash.digest_size
    mEnd = 0

    # Check to make sure the ECIES header (c[0]) is the correct value
    if c[0] == 2 or c[0] == 3 or c[0] == 4:
        rLen = int((secp256k1.size + 7) / 4)
        if len(c) < (rLen + hLen + 1):
            print(
                f"decrypt(c, s1, s2) Err Invalid Message c, (len({c}) < {rLen + hLen + 1})")
            return None
    else:
        print(f"decrypt(c, s1, s2) Err Invalid Public Key c, c[0] = {c[0]}")
        return None

    mStart = rLen
    mEnd = len(c) - hLen

    # Next, Unmarshal the ephemeral public key (ECDH pubK) from the ciphertext R
    R = unmarshal(c[:rLen])
    if not R:
        print("decrypt(c, s1, s2) Err Unable to Unmarshal Public Key to R")
        return None

    print()
    print(bytes_to_hex(R))
    print()

    # Next, generate the shared secret such that S = Px where (Px, Py) = r * Kpub
    # .. or (Px, Py) = privK * R
    S = generate_shared_secret(R, privK)
    if S is None:
        print("decrypt(c, s1, s2) Err Unable to Generate Shared Secret S")
        return None

    # Next, derive the keys using the Ke || Km = KDF(S, 32)
    Ke, Km = derive_keys(params, S, s1)

    # Next, compute the message tag and compare with the existing from the msg
    d = message_tag(params.hashAlgo, Km, c[mStart:mEnd], s2, c[mEnd:])
    if d is None:
        print("decrypt(c, s1, s2) Err Unable to Validate MAC from msg c")
        return None

    return sym_decrypt(params, Ke, c[mStart:mEnd])
