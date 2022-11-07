from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Cipher import AES

# Base ECIES params class with default of AES128 and HMAC-SHA-256-16
# .. NOTE tied to the private key public key - to ensure proper enc/dec
class ECIES_Params:
    Hash = SHA256.new()
    hashAlgo = SHA256 # SHA256
    Cipher = AES # AES128
    BlockSize = AES.block_size # block size 16
    KeyLen = AES.key_size[0] # AES128 16 (16 * 8 = 128)
    Name = "ECIES_AES128_HMAC_SHA256"
    
# DEFAULT
class ECIES_AES128_SHA256(ECIES_Params):
    Hash = SHA256.new()
    hashAlgo = SHA256 # SHA256
    Cipher = AES # AES128
    BlockSize = AES.block_size # block size 16
    KeyLen = AES.key_size[0] # AES128 16
    Name = "ECIES_AES128_HMAC_SHA256"
    
class ECIES_AES192_SHA384(ECIES_Params):
    Hash = SHA384.new()
    hashAlgo = SHA384 # SHA384
    Cipher = AES # AES192
    BlockSize = AES.block_size # block size 16
    KeyLen = AES.key_size[1] # AES192 24
    Name = "ECIES_AES192_HMAC_SHA384"
    
class ECIES_AES256_SHA256(ECIES_Params):
    Hash = SHA256.new()
    hashAlgo = SHA256 # SHA256
    Cipher = AES # AES256
    BlockSize = AES.block_size # block size 16
    KeyLen = AES.key_size[2] # AES256 32
    Name = "ECIES_AES256_HMAC_SHA256"
    
class ECIES_AES256_SHA384(ECIES_Params):
    Hash = SHA384.new()
    hashAlgo = SHA384 # SHA384
    Cipher = AES # AES256
    BlockSize = AES.block_size # block size 16
    KeyLen = AES.key_size[2] # AES256 32
    Name = "ECIES_AES256_HMAC_SHA384"
    
class ECIES_AES256_SHA512(ECIES_Params):
    Hash = SHA512.new()
    hashAlgo = SHA512 # SHA512
    Cipher = AES # AES256
    BlockSize = AES.block_size # block size 16
    KeyLen = AES.key_size[2] # AES256 32
    Name = "ECIES_AES256_HMAC_SHA512"