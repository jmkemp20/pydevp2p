from pydevp2p.utils import bytes_to_hex, bytes_to_int


class RLPxCapabilityMsg:
    """
    _summary
    """
    def __init__(self, type: str, code: int, msg: list[bytes], code_types: list, msg_types: dict) -> None:
        self.type = type
        self.code = code
        self.msg = msg
        self.code_types = code_types
        self.msg_types = msg_types
        
        self.d_msg = deserialize_rlp(msg, self.msg_types.get(self.code_types[code]))
        print()
        print(f"{type.upper()}: {code}, {self.code_types[code]}: {self.d_msg}")
        return
            
    def __str__(self) -> str:
        ret = ""
        vals = self.getValues()
        for i in range(1, len(vals)):
            ret += f"  {vals[i]}\n"
        return f"RLPxCapabilityMsg:\n{ret}"
    
    def getValues(self):
        ret = [len(self.d_msg)]
        ret.extend(self.d_msg)
        return ret
    
class EthCapabilitiy(RLPxCapabilityMsg):
    """_summary_

    Args:
        RLPxCapabilityMsg (_type_): _description_
    """
    # Code Mappings
    code_types = ["Status", "NewBlockHashes", "Transactions", "GetBlockHeaders", "BlockHeaders", "GetBlockBodies", "BlockBodies", "NewBlock",\
        "NewPooledTransactionHashes", "GetPooledTransactions", "PooledTransactions", "N/A", "N/A", "N/A", "N/A", "GetReceipts", "Receipts"]
    # Type Structures
    msg_types = {
        "Status": ["Version", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "NewBlockHashes": ["Version", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "Transactions": ["Version", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "GetBlockHeaders": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "BlockHeaders": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "GetBlockBodies": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "BlockBodies": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "NewBlock": ["Block", "Total Difficulty"],
        "NewPooledTransactionHashes": ["Version", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "GetPooledTransactions": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "PooledTransactions": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "N/A": ["Version", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "GetReceipts": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
        "Receipts": ["Request ID", "Network ID", "Total Difficulty", "Block Hash", "Genesis", "Fork ID"],
    }
    
    def __init__(self, code: int, msg: list[bytes]) -> None:
        super().__init__("eth", code, msg, self.code_types, self.msg_types)
        

class SnapCapability(RLPxCapabilityMsg):
    """_summary_

    Args:
        RLPxCapabilityMsg (_type_): _description_
    """
    # Code Mappings
    code_types = ["GetAccountRange", "AccountRange", "GetStorageRanges", "StorageRanges", "GetByteCodes", "ByteCodes", "GetTrieNodes", "TrieNodes"]
    # Type Structures
    msg_types = {
        "GetAccountRange": ["Request ID", "Root Hash", "Starting Hash", "Limit Hash", "Response Bytes"],
        "AccountRange": ["Request ID", "Accounts", "Proof"],
        "GetStorageRanges": ["Request ID", "Root Hash", "Account Hash", "Starting Hash", "Limit Hash", "Response Bytes"],
        "StorageRanges": ["Request ID", "Slots", "Proof"],
        "GetByteCodes": ["Request ID", "Hashes", "Bytes"],
        "ByteCodes": ["Request ID", "Codes"],
        "GetTrieNodes": ["Request ID", "Root Hash", "Paths", "Bytes"],
        "TrieNodes": ["Request ID", "Nodes"],
    }
    
    def __init__(self, code: int, msg: list[bytes]) -> None:
        super().__init__("snap", code, msg, self.code_types, self.msg_types)
            
    
def get_rlpx_capability_msg(code: int, msg: list[bytes]) -> RLPxCapabilityMsg | None:    
    # TODO Dynamically change msg_id blocks
    msg_id = code - 16
    if msg_id < len(EthCapabilitiy.code_types):
        # ETH
        return EthCapabilitiy(msg_id, msg)
    msg_id = msg_id - len(EthCapabilitiy.code_types)
    if msg_id < len(SnapCapability.code_types):
        # SNAP
        return SnapCapability(msg_id, msg)
    
    print(f"get_rlpx_capability_msg(code, msg) Err Unknown Capability Msg: {code}, {msg}") 
    return RLPxCapabilityMsg(msg)

def deserialize_rlp(msg: list, structure: list) -> list:
    a = [None] * len(msg)
    def get_leaves(msg: list | bytes):
        # base case
        if not isinstance(msg, list):
            if len(msg) == 0:
                return "N/A"
            elif len(msg) <= 8: # 8 bytes (64bit)
                return bytes_to_int(msg)
            else:
                return bytes_to_hex(msg)
        sub = []
        for child in msg:
            sub.append(get_leaves(child))
        return sub
    for i in range(len(msg)):
        a[i] = f"{structure[i]}: {get_leaves(msg[i])}"
    return a
    
def get_shape(msg: list):
    a = [None] * len(msg)
    def get_leaves(msg: list | bytes):
        # base case
        if not isinstance(msg, list):
            return 1
        count = 0
        for child in msg:
            count = count + get_leaves(child)
        return count
    for i in range(len(msg)):
        a[i] = get_leaves(msg[i])
    return a
    

    