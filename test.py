#!/usr/bin/python
from rlp.codec import decode, encode
from rlp.sedes import big_endian_int, binary, text, boolean, CountableList, Binary, Serializable, Text, Boolean, List
from pydevp2p.discover.v4wire.msg import decodeMessageByType
from pydevp2p.rlp.extention import RLPMessage
from pydevp2p.rlp.types import ip_address, hex_value, date_value
from pydevp2p.rlpx.capabilities import SnapCapability, get_rlpx_capability_msg

from pydevp2p.utils import bytes_to_hex, dict_to_depth_str_list, dict_to_flat_str, dict_to_str_list, hex_to_bytes

# Define a sequence of elements to encode
# .. Ping
encoded_ping = hex_to_bytes(
    "e304cb840a01010a827660827660c9840a01000a82765f8084637582f886018482f24edb")
# .. Pong
encoded_pong = hex_to_bytes(
    "f839cb840a01010a827660827660a02320af1951184f1f6c0734b468b5527fada3f382b064e65e4c33859bb8b73f6884637582f886018482f24aa2")
# .. FindNode
encoded_findnode = hex_to_bytes(
    "f847b840c35c2b7f9ae974d1eee94a003394d1cc18135e7fe6665e6b4f221970f1d9d59f6a58e76763803bcc9097eba4c91fd08b30405e65c53272b8635348e37f93cedc84637582f8")
# .. Neighbors
encoded_neighbors = hex_to_bytes("f8a5f89ef84d840a01000a82765f82765fb8402c4b6808e788537ca13ab4c35e6311bc2553b65323fb0c9e9a831303a1059b8754aab13dbb78c03a7a31beee5c2f2fb570393f056d54fa83ebd7e277039cc7b6f84d840a010214827661827661b8401ae68ad9b2b095b5366d9a725a184bf1a6a5e101a4e6a3de62b38b07eac2c8fe365e8a184004191c96d2f365f3c116c5dfbb92247635cf49a730f02908d6e3978463757b2c")
# .. ENRRequest
encoded_enrrequest = hex_to_bytes("c58463757b31")
# .. ENRResponse
encoded_enrresponse = hex_to_bytes("f8c6a07101f62a1c177cac2ae403af30fa0c39a27b0e5fe70889dc01aeb77f2b8a4b72f8a3b8401325cb60dbf7d31450f6a13391e40aebd14be5412a060fb10ed7b5ed06f933082092ff2630caa64bc663ebdf2aff5911ddaf2f4f9a4e7fe4e1d0b2ed8eba377386018482e72b8b83657468c7c684c18145ad80826964827634826970840a01010a89736563703235366b31a102c35c2b7f9ae974d1eee94a003394d1cc18135e7fe6665e6b4f221970f1d9d59f84736e6170c08374637082766083756470827660")

enc_account_range = hex_to_bytes(
    "f8828823a62343b186b51fc0f876b874f872a1206efc5f1730f31db5fc889ddc1b7695d8e7359ba754e5f7095293152a985ac2fdb84ef84c80883782dace9d900000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

dec = decode(enc_account_range,
             sedes=SnapCapability.AccountRange, strict=False)
print("------------------------------------------------------")
cleanse = dec.as_str_list()
for string in cleanse:
    print(string)
