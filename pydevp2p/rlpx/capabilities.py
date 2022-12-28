from rlp.codec import decode
from rlp.sedes import big_endian_int, CountableList
from pydevp2p.rlp.extention import RLPMessage
from pydevp2p.rlp.types import VariableList, hex_value, hex_or_int_value
from pydevp2p.rlpx.types import RLPxCapabilityMsg
from pydevp2p.utils import framectx


class BlockHash(RLPMessage):
    fields = (("Block_Hash", hex_value), ("Number", big_endian_int))


class BlockHeader(RLPMessage):
    # ,("Unknown", big_endian_int)
    fields = (("Parent_Hash", hex_value), ("Ommers_Hash", hex_value), ("Coinbase", hex_value), ("State_Root", hex_value), ("Txs_Root", hex_value), ("Receipts_Root", hex_value), ("Bloom", hex_value), ("Difficulty", big_endian_int),
              ("Number", big_endian_int), ("Gas_Limit", big_endian_int), ("Gas_Used", big_endian_int), ("Time", big_endian_int), ("Extra_Data", hex_value), ("Mix_Digest", hex_value), ("Block_Nonce", hex_value))


class LegacyTransaction(RLPMessage):
    fields = (("Nonce", big_endian_int), ("Gas_Price", big_endian_int), ("Gas_Limit", big_endian_int), ("Recipient",
              hex_value), ("Value", big_endian_int), ("Data", hex_value), ("V", big_endian_int), ("R", big_endian_int),
              ("S", big_endian_int))


class BlockBody(RLPMessage):
    # TODO There could be typed-transactions
    fields = (("Transactions", CountableList(LegacyTransaction)),
              ("Ommers", CountableList(BlockHeader)))


class FullBlock(RLPMessage):
    # TODO There could be typed-transactions
    fields = (("Header", BlockHeader), ("Transactions", CountableList(LegacyTransaction)),
              ("Ommers", CountableList(BlockHeader)))


class EthCapabilitiy(RLPxCapabilityMsg):
    """_summary_

    Args:
        RLPxCapabilityMsg (_type_): _description_
    """

    # Main Message Types
    class Status(RLPMessage):
        # class ForkId(RLPMessage):
        #     fields = (("Fork_Hash", hex_value), ("Fork_Next", hex_value))
        fields = (("Version", big_endian_int), ("Network_ID", big_endian_int),
                  ("Block_Hash", hex_value), ("Genesis", hex_value), ("Fork_Hash", hex_value), ("Fork_Next", hex_value))

    class NewBlockHashes(RLPMessage):
        fields = [("Block_Hashes", VariableList(BlockHash))]

    class Transactions(RLPMessage):
        # TODO There could be typed-transactions
        fields = [("Transactions", VariableList(LegacyTransaction))]

    class GetBlockHeaders(RLPMessage):
        class BlockHeadersRequest(RLPMessage):
            fields = (("Start_Block", hex_or_int_value), ("Limit", big_endian_int),
                      ("Skip", big_endian_int), ("Reverse", big_endian_int))
        fields = (("Request_ID", big_endian_int),
                  ("Request", BlockHeadersRequest))

    class BlockHeaders(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Headers", CountableList(BlockHeader)))

    class GetBlockBodies(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Block_Hashes", CountableList(hex_value)))

    class BlockBodies(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Block_Bodies", CountableList(BlockBody)))

    class NewBlock(RLPMessage):
        fields = (("Block", FullBlock), ("Total_Difficulty", big_endian_int))

    class NewPooledTransactionHashes(RLPMessage):
        # Below is the eth/66 EIP-2481 standard
        # fields = [("Transaction_Hashes", VariableList(hex_or_int_value))]
        # eth/68 standard go-ethereum/eth/protocols/eth/protocol.go
        fields = (("Types", hex_or_int_value), ("Sizes",
                  CountableList(big_endian_int)), ("Hashes", CountableList(hex_value)))

    class GetPooledTransactions(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Transaction_Hashes", CountableList(hex_value)))

    class PooledTransactions(RLPMessage):
        # TODO There could be typed-transactions
        fields = (("Request_ID", big_endian_int),
                  ("Transactions", CountableList(LegacyTransaction)))

    class GetReceipts(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Block_Hashes", CountableList(hex_value)))

    class Receipts(RLPMessage):
        # TODO There could be typed-receipts
        class Receipt(RLPMessage):
            class Log(RLPMessage):
                fields = (("Contract_Address", hex_value), ("Topics", CountableList(hex_value)),
                          ("Data", hex_value))
            fields = (("Post_State_Or_Status", hex_or_int_value), ("Cumulative_Gas", big_endian_int),
                      ("Bloom", hex_value), ("Logs", CountableList(Log)))
        fields = (("Request_ID", big_endian_int),
                  ("Receipts", CountableList(CountableList(Receipt))))

    # Code Mappings
    code_types: list[RLPMessage | None] = [Status, NewBlockHashes, Transactions, GetBlockHeaders, BlockHeaders,
                                           GetBlockBodies, BlockBodies, NewBlock, NewPooledTransactionHashes,
                                           GetPooledTransactions, PooledTransactions, None, None, None, None,
                                           GetReceipts, Receipts]

    def __init__(self, code: int, raw: bytes) -> None:
        msg_type = self.code_types[code]
        name = msg_type.__name__ if msg_type is not None else "UNKNOWN"
        super().__init__("eth", code, name)

        dec = None
        if msg_type is None:
            print(f"{framectx()} ETH Unimplemented/Unknown Msg Code {code}")
            return
        try:
            dec = decode(raw, sedes=msg_type, strict=False)
            self.fields = dec.as_str_list()
        except BaseException as e:
            print(
                f"{framectx()} ETH Err Unable to Decode Msg ({code}) {name} : {e}")
            dec = decode(raw, strict=False)
            print(dec)
            return
        if not isinstance(dec, RLPMessage):
            print(f"{framectx()} ETH Err Invalid Msg Type ({code}) {name} : {dec}")
            return


class SnapCapability(RLPxCapabilityMsg):
    """_summary_

    Args:
        RLPxCapabilityMsg (_type_): _description_
    """
    class GetAccountRange(RLPMessage):
        fields = (("Request_ID", big_endian_int), ("Root_Hash", hex_value), ("Starting_Hash",
                  hex_value), ("Limit_Hash", hex_value), ("Stop_Bytes", big_endian_int))

    class AccountRange(RLPMessage):
        class Account(RLPMessage):
            class AccountSlimBody(RLPMessage):
                # https://ethereum.org/en/developers/docs/accounts/
                fields = (("Nonce", hex_value), ("Balance", hex_value),
                          ("Code_Hash", hex_value), ("Storage_Root", hex_value))
            fields = (("Account_Hash", hex_value),
                      ("Account_Body", AccountSlimBody))

        accounts = CountableList(Account)

        fields = (("Request_ID", big_endian_int), ("Accounts",
                  accounts), ("Proof", CountableList(hex_value)))

    class GetStorageRanges(RLPMessage):
        fields = (("Request_ID", big_endian_int), ("Root_Hash", hex_value), ("Account_Hashes", CountableList(
            hex_value)), ("Starting_Hash", hex_value), ("Limit_Hash", hex_value), ("Response_Bytes", big_endian_int))

    class StorageRanges(RLPMessage):
        class Slot(RLPMessage):
            fields = (("Slot_Hash", hex_value), ("Slot_Data", hex_value))
        fields = (("Request_ID", big_endian_int), ("Slots", CountableList(
            CountableList(Slot))), ("Proof", CountableList(hex_value)))

    class GetByteCodes(RLPMessage):
        fields = (("Request_ID", big_endian_int), ("Hashes",
                  CountableList(hex_value)), ("Bytes", big_endian_int))

    class ByteCodes(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Codes", CountableList(hex_value)))

    class GetTrieNodes(RLPMessage):
        fields = (("Request_ID", big_endian_int), ("Root_Hash", hex_value), ("Paths",
                  CountableList(CountableList(hex_value))), ("Bytes", big_endian_int))

    class TrieNodes(RLPMessage):
        fields = (("Request_ID", big_endian_int),
                  ("Nodes", CountableList(hex_value)))

    # Code-Type Mappings
    code_types: list[RLPMessage] = [GetAccountRange, AccountRange, GetStorageRanges,
                                    StorageRanges, GetByteCodes, ByteCodes, GetTrieNodes, TrieNodes]

    def __init__(self, code: int, raw: bytes) -> None:
        msg_type = self.code_types[code]
        name = msg_type.__name__ if msg_type is not None else "UNKNOWN"
        super().__init__("snap", code, name)

        dec = None
        if msg_type is None:
            print(f"{framectx()} SNAP Unimplemented/Unknown Msg Code {code}")
            return
        try:
            dec = decode(raw, sedes=msg_type, strict=False)
            self.fields = dec.as_str_list()
        except BaseException as e:
            print(f"{framectx()} SNAP Err Unable to Decode Msg : {e}")
            return
        if not isinstance(dec, RLPMessage):
            print(f"{framectx()} SNAP Err Invalid Msg Type : {dec}")
            return


def get_rlpx_capability_msg(code: int, raw: bytes) -> RLPxCapabilityMsg | None:
    # TODO Dynamically change msg_id blocks
    msg_id = code - 16
    if msg_id < len(EthCapabilitiy.code_types):
        # ETH
        return EthCapabilitiy(msg_id, raw)
    msg_id = msg_id - len(EthCapabilitiy.code_types)
    if msg_id < len(SnapCapability.code_types):
        # SNAP
        return SnapCapability(msg_id, raw)

    print(f"{framectx()} get_rlpx_capability_msg(code, msg) Err Unknown Capability Msg: {code}")
    return RLPxCapabilityMsg("UNKNOWN", msg_id, "N/A")
