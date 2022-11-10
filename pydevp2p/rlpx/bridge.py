
# This file is a bridge to handle payload data incoming from a LUA dissector
from pydevp2p.rlpx.node import Node
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4
from pydevp2p.utils import hex_to_bytes


boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"

all_nodes: dict[str, Node] = {
    "10.1.0.10": Node("10.1.0.10", hex_to_bytes(boot_priv_static_k)),
    "10.1.1.10": Node("10.1.1.10", hex_to_bytes(node1_priv_static_k)),
    "10.1.2.20": Node("10.1.2.20", hex_to_bytes(node2_priv_static_k)),
    "10.1.3.30": Node("10.1.3.30", hex_to_bytes(node3_priv_static_k))
}

def handleRLPxHandshakeMsg(srcip: str, dstip: str, payload: str) -> AuthMsgV4 | AuthRespV4 | None:
    src_node = all_nodes.get(srcip)
    dst_node = all_nodes.get(dstip)
    if src_node is None or dst_node is None:
        return None
    
    dec = None
    try:
        dec = dst_node.readHandshakeMsg(hex_to_bytes(payload), src_node)
    except BaseException as e:
        print(f"[BRIDGE] handleAuthMsg(srcip, dstip, payload) {e}")
        return None
    if dec is None:
        print(f"[BRIDGE] handleAuthMsg(srcip, dstip, payload) Unable to readHandshakeMsg()")
        return None
    
    return dec.getValues()