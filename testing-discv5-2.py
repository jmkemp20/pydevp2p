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
    print(f"{node.ipaddr} Enode ID: {bytes_to_hex(node.discv5.localEnodeID)}")

#############################################################
# DISCV5 UNKNOWN 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#############################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("c30333ea9ec3989e67939b021049ab37439c08b6ed3bf044eec99eef3e51b5d1ac047a26a2d79db4af3ac09458f3830aaecdd46d0d99992521bb31a0acc59c56351a86997d76bedad0a3921077331b52ce19e27aee2ec6317cfb05"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
# if msg is not None:
#     print(f"{msg_src} → {msg_dst}")
#     header, packet = msg
#     print(header)
#     print(packet)
# print()

#############################################################
# discv5 WHOAREYOU 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#############################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("fad2c80b2888d1b1dad1df44772eec1f6145e7e91b7de6d7e797130274ddb56dceaf64f8d1069a53aa5c2a4779b258d236c980e3429f40180fdee84be96c30"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
# if msg is not None:
#     header, packet = msg 
#     print(f"{msg_src} → {msg_dst}")
#     print(header)
#     print(packet)
# print()

#############################################################
# DISCV5 HANDSHAKE 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#############################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("e73fd63067b11426f35c112cada234b2d275a10ecb9d40ed23048ec4f506bb2d184b61ce04e7c6e285c527df53d0fc563452a2f7fc946ae84d70993da4ac70ebb3d002426b17989ffde432b1b239b5987b62c23fc6f259f2afeb032a4c6124e28bba427578097410f70b450ddade41413fab1ea4b0f82fe32139c2e56665d69553a4078e95ae8660ad798b6a41156feadca2ccdcacfb653a55c74c5457890fa7835f41ec1644da89fb602fad57256141447793fdae4b69733acc7931c1fc47e14d81deccbdfb63dc0ce3a2d01e721417231a1f90337c75c13dd6831c5616b19225c88183bcce1f92d14ff03694f92b67dd5be41954772ca40238743cfe37149f4f289f2cd97b2e1862d6bd29fc90751b3c7d936e21fb61f8875c64ce27a0ff72dd22c9b8d2e61cb2058b1d9f03be9db2d86ceeb70dfb90805bdb0587e1e39637b818db7fa41093cbd203fb5e238fe201b3d8112783df4dd8bedc62a7ab0d9251506306ea333e4650140cb807ff851b8226e8"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

# 