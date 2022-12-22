
from pydevp2p.elliptic.curve import encode_pubkey
from pydevp2p.elliptic.utils import pubk_to_idv4
from pydevp2p.utils import bytes_to_hex, bytes_to_int


class pair:
    """
    pair is a key/value pair in a record.
    """
    def __init__(self, k: str, v: bytes) -> None:
        self.k = k
        self.v = v
        
    def __str__(self) -> str:
        cleansedVal = self.v
        if isinstance(self.v, bytes):
            cleansedVal = bytes_to_hex(self.v) if len(self.v) > 8 else bytes_to_int(self.v)
        return f"({self.k}: {cleansedVal})"

class Record:
    """
    Record represents a node record. The zero value is an empty record.
    """
    def __init__(self, raw: bytes) -> None:
        self.raw: bytes = raw # RLP encoded record
        sig, seq, *pairs = raw
        self.sig: bytes = sig # the signature
        self.seq: int = bytes_to_int(seq) # sequence number
        self.pairs: list[pair] = [] # sorted list of all key/value pairs
        self.pubk: bytes = None # compressed secp256k1 pubk 33 bytes
        for i in range(0, len(pairs), 2):
            p = pair(pairs[i].decode('utf-8'), pairs[i+1])
            if p.k == "secp256k1":
                self.pubk = pubk_to_idv4(encode_pubkey(p.v, "bin_electrum"))
            self.pairs.append(p)
    
    def __str__(self) -> str:
        ret = f"ENR Record:"
        for attr, val in self.__dict__.items():
            cleansedVal = val
            if isinstance(val, bytes):
                cleansedVal = bytes_to_hex(val) if len(val) > 8 else bytes_to_int(val)
            if isinstance(val, list):
                temp = ""
                for v in val:
                    temp += str(v) + ", "
                cleansedVal = temp[:len(temp) - 2] if len(temp) > 2 else temp
            ret += f"\n  {attr.capitalize()}: {cleansedVal}"
        return ret
        
class Enode:
    """
    Node represents a host on the network with an ENR Record and Pubk pair
    """
    def __init__(self, enrRecord: Record, pubk: bytes) -> None:
        self.enrRecord = enrRecord
        self.pubk = pubk # 32 byte pubk unique ID of node