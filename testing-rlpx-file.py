#!/usr/bin/python
import json
from pydevp2p.rlpx.node import Node
from pydevp2p.utils import hex_to_bytes
from time import sleep

# NOTE The goal is to show step by step how things should be done with RLPx

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

with open('out.json', 'r') as f:
    data = json.load(f)

for idx, packet in enumerate(data):
    src, dst, payload, type, visited, number = packet.values()
    src_node, dst_node = all_nodes.get(src), all_nodes.get(dst)
    print(f"{number}) {src} → {dst}")
    if type == "rlpx-handshake":
        msg = dst_node.readHandshakeMsg(hex_to_bytes(payload), src_node)
        print(msg)
    elif type == "rlpx-msg":
        msg = dst_node.readRLPxMsg(hex_to_bytes(payload), src_node)
        header, packet = msg
        print(header)
        print(packet)
        if number == 195:
            break
    elif type == "discv4":
        pass
    elif type == "discv5":
        pass
    else:
        pass
    print()
