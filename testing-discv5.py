#!/usr/bin/python
from pydevp2p.rlpx.node import Node
from pydevp2p.utils import hex_to_bytes, bytes_to_hex

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

for node in all_nodes.values():
    print(f"{node.ipaddr} Pubk: {bytes_to_hex(node.pubK)}")

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("b6eebd128ceb6ecce8be7bf9818d835004b9e96c93c93062b81844c56a13cbb3c50ceac7cee754b3356168c15daf5b17d4a711b4a646943c673f9606844d40a27f82e7c4eb88c5a028f9a8903e96bbfef35f4e38bd54d49a5ab0cf"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
print(msg)
