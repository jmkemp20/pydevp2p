
# This file is a bridge to handle payload data incoming from a LUA dissector
from pydevp2p.rlpx.node import Node
from pydevp2p.utils import hex_to_bytes


all_nodes: dict[str, Node] = {}

# VMWare Geth Nodes
# boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
# node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
# node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
# node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"
# bootnode = Node("192.168.2.20", hex_to_bytes(boot_priv_static_k))
# node1 = Node("192.168.3.30", hex_to_bytes(node1_priv_static_k))
# node2 = Node("192.168.4.40", hex_to_bytes(node2_priv_static_k))
# node3 = Node("192.168.5.50", hex_to_bytes(node3_priv_static_k))

# Geth Docker Nodes
boot_priv_static_k = "b0ac22adcad37213c7c565810a50f1772291e7b0ce53fb73e7ec2a3c75bc13b5"
node1_priv_static_k = "f78d350a7505b4bbcdd543425dc0ecf999683072c59c6e1f77579d01435b530a"
node2_priv_static_k = "754560155b48296a1f98e6b125bc9dff9625be400afe6fcb0ca2f35dea956520"
bootnode = Node("10.1.1.10", hex_to_bytes(boot_priv_static_k))
node1 = Node("10.1.2.20", hex_to_bytes(node1_priv_static_k))
node2 = Node("10.1.3.30", hex_to_bytes(node2_priv_static_k))
