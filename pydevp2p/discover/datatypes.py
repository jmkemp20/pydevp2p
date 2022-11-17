
class pair:
    """
    pair is a key/value pair in a record.
    """
    def __init__(self, k: str, v: bytes) -> None:
        self.k = k
        self.v = v

class Record:
    """
    Record represents a node record. The zero value is an empty record.
    """
    def __init__(self, seq: int, sig: bytes, raw: bytes, pairs: list[pair]) -> None:
        self.seq = seq # sequence number
        self.sig = sig # the signature
        self.raw = raw # RLP encoded record
        self.pairs = pairs # sorted list of all key/value pairs
        
class Enode:
    """
    Node represents a host on the network with an ENR Record and Pubk pair
    """
    def __init__(self, enrRecord: Record, pubk: bytes) -> None:
        self.enrRecord = enrRecord
        self.pubk = pubk # 32 byte pubk unique ID of node