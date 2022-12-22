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
    

#################################################
# PING 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("2320af1951184f1f6c0734b468b5527fada3f382b064e65e4c33859bb8b73f6803a804fadf77b01ab6bceef1881f7eea01e0ac5d06dc9bd976592f36903b63771c95cfc71f8d5b984b4d53f48202350d5b4a8c364370760af2404a67198df12b0101e304cb840a01010a827660827660c9840a01000a82765f8084637582f886018482f24edb"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

#################################################
# PONG 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("81e76240e05980cb8f66fea7dca9b06996abdf3e2c4323986800435d5c4eb0deff594eeeb54e3d82efc47376e8a48f2487e47dc785dbc18593b1bc1351d42d3e01b5db1d165962ac680427e2e505fb9fa45445fa67b45e0ce0fc1e84739b93390102f839cb840a01010a827660827660a02320af1951184f1f6c0734b468b5527fada3f382b064e65e4c33859bb8b73f6884637582f886018482f24aa2"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

#####################################################
# FINDNODE 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#####################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("db29490536d027389c9ef9ccf136162f2302807d13663944d652672fcf9e0436486ed83f8f738a0e2e0dbb77989c05837f32b5c8638828f17522774508fd0de62816992ffee162f917dc4167f653b6ca1e56a85c5638cef78462ddc92268d91a0003f847b840c35c2b7f9ae974d1eee94a003394d1cc18135e7fe6665e6b4f221970f1d9d59f6a58e76763803bcc9097eba4c91fd08b30405e65c53272b8635348e37f93cedc84637582f8"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

######################################################
# NEIGHBORS 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
######################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("4c8caac500e4a9dd2d26fbb78b549882483622b196d28f79111cdb4984cb3d614fab3a93f17aafa6bdcac5c55d8c874b34630615292c85139a7d01e5f1f17fc107fb74f23cc1b8d3887c62774cbe2e37f4bcface4bc4a1265b78a65fa10080c40104f8a5f89ef84d840a01000a82765f82765fb8402c4b6808e788537ca13ab4c35e6311bc2553b65323fb0c9e9a831303a1059b8754aab13dbb78c03a7a31beee5c2f2fb570393f056d54fa83ebd7e277039cc7b6f84d840a010214827661827661b8401ae68ad9b2b095b5366d9a725a184bf1a6a5e101a4e6a3de62b38b07eac2c8fe365e8a184004191c96d2f365f3c116c5dfbb92247635cf49a730f02908d6e3978463757b2c"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

#######################################################
# ENRRequest 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#######################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("7101f62a1c177cac2ae403af30fa0c39a27b0e5fe70889dc01aeb77f2b8a4b72c3be5d2c1b583e2b6727ecd57b39e6d48c9015a28cb4694c2cfac62b9f5418fa686cba5010407c426ef097ccdada8a8cdff2323af4035d1980c2657166df03fd0105c58463757b31"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

########################################################
# ENRResponse 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
########################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("fa169dd97ea1d93a109623306cf10b2280e4d6e4256e160f6bf4f9dba43a7aa49135aaacabe6c85811cc0758945fd78e3dc943e1d6e29a1d23fd40fe660d0dc14b9f3687db45665de100febaa88ec3d59ec88c2c032be7f6c233af5e883814c90106f8c6a07101f62a1c177cac2ae403af30fa0c39a27b0e5fe70889dc01aeb77f2b8a4b72f8a3b8401325cb60dbf7d31450f6a13391e40aebd14be5412a060fb10ed7b5ed06f933082092ff2630caa64bc663ebdf2aff5911ddaf2f4f9a4e7fe4e1d0b2ed8eba377386018482e72b8b83657468c7c684c18145ad80826964827634826970840a01010a89736563703235366b31a102c35c2b7f9ae974d1eee94a003394d1cc18135e7fe6665e6b4f221970f1d9d59f84736e6170c08374637082766083756470827660"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()

#########################################################
# DISCV5 Check 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#########################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("e73fd63067b11426f35c112cada234b2d275a10ecb9d40ed23048ec4f506bb2d184b61ce04e7c6e285c527df53d0fc563452a2f7fc946ae84d70993da4ac70ebb3d002426b17989ffde432b1b239b5987b62c23fc6f259f2afeb032a4c6124e28bba427578097410f70b450ddade41413fab1ea4b0f82fe32139c2e56665d69553a4078e95ae8660ad798b6a41156feadca2ccdcacfb653a55c74c5457890fa7835f41ec1644da89fb602fad57256141447793fdae4b69733acc7931c1fc47e14d81deccbdfb63dc0ce3a2d01e721417231a1f90337c75c13dd6831c5616b19225c88183bcce1f92d14ff03694f92b67dd5be41954772ca40238743cfe37149f4f289f2cd97b2e1862d6bd29fc90751b3c7d936e21fb61f8875c64ce27a0ff72dd22c9b8d2e61cb2058b1d9f03be9db2d86ceeb70dfb90805bdb0587e1e39637b818db7fa41093cbd203fb5e238fe201b3d8112783df4dd8bedc62a7ab0d9251506306ea333e4650140cb807ff851b8226e8"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv4Msg(msg, src_node)
if msg is not None:
    print(f"{msg_src} → {msg_dst}")
    header, packet = msg
    print(header)
    print(packet)
print()