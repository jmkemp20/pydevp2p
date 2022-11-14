from pydevp2p.rlpx.types import RLPxCapabilityMsg
    
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
