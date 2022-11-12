#!/usr/bin/python
from pydevp2p.crypto.secp256k1 import privtopub
from pydevp2p.crypto.utils import xor
from pydevp2p.rlpx.node import Node
from pydevp2p.utils import bytes_to_hex, hex_to_bytes

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

# NOTE currently we are not adding connections or known peers based on UDP discovery

############################################################
# AUTH INIT 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
############################################################
# .. given from LUA (src: str, dst: str, data: str)
auth_init_src, auth_init_dst, auth_init_msg = ("10.1.1.10", "10.1.0.10", \
    "01b1045380d862109ae2b4fc80d629bed8f2c1ff1d962749372a7bea4a36873f5f07ffc035ed32e107f3c39fae236764c37cbb6d45d10088c4c24f23fec8e44e302dc7cb760be4df28aad92c5046ec7364859ec001bf39a92ce294a114ca42f35f5d1e1c3f25660f1e23b3bce9010863299e8a0634a49998adc106ede01ff51280fe97f17a228726cafcab8d1e23c988382d7bc5444100ee8f869bd1513d17fda3d8b94f979ef495258253587481485297c896605b3aad6bf44d18c73ef7528a56364d2bfd47c6d2b0f49fe6b7bf47b75a1c3d6b922ccc653c905ca3f7a00a47757f44a9cd59426f983abde8ecebe80fa6d3542209378436b3dbbb2cc4f7d3b9fa6d84a384f00929af02223a645c5f5cb8177d4d309c33b5d00484004dce04b4ef4c692fcfabaa786bcb5722da0000b47fd32d9f11763b529e8846c1fb628d9f37b18f475595fe1a20df5da8878a39ae50f06abd4472f66f8ded7035ff12d63b76f2107254fc655e37c413ebf2e5dce4f5c035dd3f9faed6f3985ef7a75a4d4b7be28f28240bb53ffea06247ba83ae40a4bd2526d480cda19a0b81b29b95ed103905a2721865e5ada16d8151bb160bc71810a9")

# Get the Nodes via ip addr, if these do not exist (None) then these should added just because
auth_init_src_node, auth_init_dst_node = all_nodes.get(auth_init_src), all_nodes.get(auth_init_dst)

# Time for dst node to read the AUTH INIT
msg = auth_init_dst_node.readHandshakeMsg(auth_init_msg, auth_init_src_node)
# AuthMsgV4:
#   Signature:            ec31947508410743633c33b6602bb1d2b4123c58c91bd90d4053d8445c5f7b75704c8d8a122f6bfadcdbe1885e6ab785305d044015c7050b3dbdda4261946f0901
#   InitatorPubkey:       e98d53b2a12bdb4441d825d4b0a1c4255b880c2f657c0adece61cbe11c5869ae35fd6bc956b3f8a2364b314eda761ebb570764c127efd5c114910a71ddfc7c4a
#   Nonce:                144045e97cd69e8255732b9fe78f81d51b572980cd944564a685306c4193e0fd
#   Version:              4
#   RandomPrivKey:        b79692695348371e67532034477e39fd280bc72cda58466ae5ac361c8f32d1ae
# print(f"{auth_init_src} → {auth_init_dst}", msg)
# print()

# print("After AUTH INIT")
# print(auth_init_src, auth_init_src_node.peers.get(auth_init_dst).handshakeState)
# print(auth_init_dst, auth_init_dst_node.peers.get(auth_init_src).handshakeState)
# print()

############################################################
# AUTH RESP 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
############################################################
auth_resp_src, auth_resp_dst, auth_resp_msg = ("10.1.0.10", "10.1.1.10", \
    "0194043037a7d8c85e7adb71335d4e2252165565f29da413a3b479032286e277bdf0b628735362223fc78b692f7650dfcf5ea3e897901eb85cfaf09e161941c515742adfa26bf20c7f8580dea24349a4bda0fd8284ee1aa6ca7426f9e721ebbb1ab61df92d6bf6ef844f0f90b2f80d8b62dc2ad0a4eec0c89badaa6758ecdfcdd2566656eefc7edd284111d21df82577f07c0760994c144e4b95c8ee6ce93c56405212b2c0e519cbfe1aea2f5993be8ca04209edb84d71345caba4e46b846801b9a34da7ecf9868dd59f9982146e8a08a53ac6514ab42f10e05f93a5e854bdac7f54e93817a8933e6b61afff989d3d14eb6eeb8b90020d061fd9ccea2b3da1f63b967bada2cf5d6c84a7f557674a5f5bf5d5567c75e08f4bfef2c8932bc72cc634ab7f736606decb3e68c468b4885c330798629ffd9cbd99689dfc74b7437e283469df488a48482172635d50bcd90dfa5558feeabec9244fa7511483a15822aba2ad64b7afd0e4ee6d2b73a35854c7b805fedf29e134ae7786e05acfc47b90eb5274f31795102c1280f144c59188acaa6f13cb428e80")
auth_resp_src_node, auth_resp_dst_node = all_nodes.get(auth_resp_src), all_nodes.get(auth_resp_dst)
msg = auth_resp_dst_node.readHandshakeMsg(auth_resp_msg, auth_resp_src_node)

# AuthRespV4:
#   RandomPubkey:         22ee4da751006e7701442371ac5c0972414ca314a31aaf117d034c9cc0d9015eace02d3ce557c71e73a3a24b455a312647f09f6bcf20cc8fce850e5f9aeb9207
#   Nonce:                eb5140c05fa17edacd9c4eadda3179a2b433335d53e8d2888fc5591fcf95a3b0
#   Version:              4
#   RandomPrivKey:        2f1c59b5acabc39a92a1c6fe92d4efaf4c577331101122b6690051421391cebb
# print(f"{auth_resp_src} → {auth_resp_dst}", msg)
# print()

# bootnode → node1
src_handshake = auth_resp_src_node.peers.get(auth_resp_dst).handshakeState
# node1 → bootnode
dst_handshake = auth_resp_dst_node.peers.get(auth_resp_src).handshakeState
print("BOOTNODE")
print(f"{auth_resp_src} → {auth_resp_dst}", src_handshake)
print("NODE1")
print(f"{auth_resp_dst} → {auth_resp_src}", dst_handshake)
print()


print("Secrets")
# # bootnode → node1
src_secrets = auth_resp_src_node.peers.get(auth_resp_dst).secrets
# # node1 → bootnode
dst_secrets = auth_resp_dst_node.peers.get(auth_resp_src).secrets
print(f"{auth_resp_src} → {auth_resp_dst}", src_secrets)
print(f"{auth_resp_dst} → {auth_resp_src}", dst_secrets)
print()

# print(dst_secrets.aes, len(dst_secrets.aes), len(dst_secrets.mac))
# print(len("006e46496c9308dbecb80b30e85f61ae"))


############################################################
# RLPx Frame 10.1.0.10 → 10.1.1.10 (bootnode → node1)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.0.10", "10.1.1.10", \
    "006e46496c9308dbecb80b30e85f61ae2d66f0bd0a92f5b1e89c3ddf72cdf34579d106bb1ba2c2e7eb5e5eace81b0714c30a5bac06861c1fdd0fccd4e543fe679f38f28d1d545b902210931809824fe39287bdf2d319d27ac9286bd3c16038efb3a5f9a58846ab8ae6dbb59145f1e21ccb64acfbcf69eb3c017c11d01ae3b7e1f5b8a6094c9e555d42f8f1c20c7903758b5a060a2a1895d97cdf103615a45c01174af0a3f26909372a0fa9e626274503851068cd8d00012fa59311f50ef795a6a9463938b1806a7ef836a053d3f289ba")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

dec = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(dec)

############################################################
# RLPx Frame 10.1.1.10 → 10.1.0.10 (node1 → bootnode)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.1.10", "10.1.0.10", \
    "006e46496c9308dbecb80b30e85f61aedcee07cf821b855e61fbe5fbc89afce779d106bb1ba2c2e7eb5e5eace81b0714c30a5bac06861c1fdd0fccd4e543fe679f38f28d1d545b902210931809824fe39287bdf2d319d27ac9286bd3c16038efb3a5f9a58846ab8ae6dbb59145f1e21ccb64acfbcf69eb3c017c11d01ae3b70ee2fbd1742db9f812910632affbb97348cbb22acfb74a600cddd56366c9ea443fe51caa7b0a92ffdd8c5ae37316d87b43fc710865eb883aa72139858901feffa6485907e7e902deabbff81886edfceed2")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

dec = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(dec)

############################################################
# RLPx Frame 10.1.0.10 → 10.1.1.10 (bootnode → node1)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.0.10", "10.1.1.10", \
    "d7886d49fd10eceaa4af60bc2087be744cfa69645930768d37d49ebc003150c5aedbb43f06f2029e4a2f5af98e57f69c48e4a615f33f2c87edf7a9a7bf1da2cd2757ee68b8968f636fa014847639b7c9ec4b02d5fb0d434c29504d7c988159573003186b126592eb8d2f8f074dcdf3a2")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

dec = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(dec)

############################################################
# RLPx Frame 10.1.1.10 → 10.1.0.10 (node1 → bootnode)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.1.10", "10.1.0.10", \
    "d7886d49fd10eceaa4af60bc2087be74c700c9a3d67a8b11c7b6e487ce794c43aedbb43f06f2029e4a2f5af98e57f69c48e4a615f33f2c87edf7a9a7bf1da2cd2757ee68b8968f636fa014847639b7c9ec4b02d5fb0d434c29504d7c98815957b81e61ffcc3a11c4922c5c21318e6901")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

dec = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(dec)
