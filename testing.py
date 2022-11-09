#!/usr/bin/python
from pydevp2p.crypto.utils import xor
from pydevp2p.rlpx.node import Node
from pydevp2p.utils import bytes_to_hex, hex_to_bytes

# NOTE The goal is to show step by step how things should be done with RLPx

boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"

all_nodes: dict[str, Node] = {
    "192.168.2.20": Node("192.168.2.20", hex_to_bytes(boot_priv_static_k)),
    "192.168.3.30": Node("192.168.3.30", hex_to_bytes(node1_priv_static_k)),
    "192.168.4.40": Node("192.168.4.40", hex_to_bytes(node2_priv_static_k)),
    "192.168.5.50": Node("192.168.5.50", hex_to_bytes(node3_priv_static_k))
}

# NOTE currently we are not adding connections or known peers based on UDP discovery

############################################################
# AUTH INIT 192.168.5.50 → 192.168.2.20 (node3 → bootnode) #
############################################################
# .. given from LUA (src: str, dst: str, data: str)
auth_init_src, auth_init_dst, auth_init_msg = ("192.168.5.50", "192.168.2.20", \
    "01b104045179bdc8f94cf063368c706bcf1e63b6fc80386576c375376200f50fdea4e54b224996cc438ca748fc4acd4948f1c95b8118e5487f4205f174eaa6ea73f0c11d459b6dc035a9e81f3d48972cdd4cef845f9e0f2ebdb9bbeaa0de0caec972cc92b07013b5954d3146760be13e650367f32e3b4f0c6f24addf0ae827a8e8a5b16343c7fd09ea287ca5a08e6f3ac957a6429781b041ff80451f781a92a44056cdd599119cf5232f79be43428e0dc28ac4b8c8887ff740af6a65674433669a217febf7232dccd0b245dd3c48a474aaa1e5f3f60a9fafc8ab03375a379c9edb7fc03324ff070e308f3384bd5c0b278ca86bfafc8fc269a964da4a9c2e5265081bcdad3ecc42582480047c585d9652b845af0a6f136143ef256bce6e3a67912cfef04378f8e6c76319258dbae248d90e18e241d8829b31dde54153cdd602feb1041e4ec26b18cd8fd8f6f3708812f7f4d495c204b056fe8b3331b6d7f6d865a6ef03e603c2f021905560fb53f4c197707e5c1c80452c89c2dec5424a1e356fe26a67b6c6cb1429ef3f0813c96cd717d78eb12dcc0addc4fe17894abe69106f374d3b4221d3d279a0cbdcb9e405af6d28ddf9")

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
# AUTH RESP 192.168.2.20 → 192.168.5.50 (bootnode → node3) #
############################################################
auth_resp_src, auth_resp_dst, auth_resp_msg = ("192.168.2.20", "192.168.5.50", \
    "0178040810f833ac009138f61715372e66e2131569be96e5b8fb01683e89b39eedb761ee753f7955d42adeda6e4354f3f17c7322a64b7decea83678213c429e931e4be9affccf51dd0605fd049be282f3e881c1e046ae2e136e157402160bd2cfc14f90dec5545659145e357c8cd45338a4e4292ff98c19738c1c3f97eb6f0e2f1e69f091b7d855855069bf2bbaeb5bf65a17f68b54c7b80fcdb9038419a12b4fdca851a574eb6dd1f477b1654b6daf84f0461b74f26a03adf5cc29a7b0f40e26477ba6445d75bcc246d5fe02dc213ab9bb69172d72a827e9e452b747b5936b3f2bbed20a76adeee07ac97b079a4240d19c0c10bbd01867cfa170c07225062fe8ae6af2ab08759e9f4b6c8153fbd945320b2367e140dea79de9e21c3e2bcfe2f53c3e503057e26766742a39f71375ff7f394056d24647dfcfaae12d7631bc23710b0ff9f21b92b9cb6abda7927a9a1156d964b0e9327c9d9f0fa5194c120a9e31ca950691312056231b915e639709a7825fdf562c2ede47f52d8")
auth_resp_src_node, auth_resp_dst_node = all_nodes.get(auth_resp_src), all_nodes.get(auth_resp_dst)
msg = auth_resp_dst_node.readHandshakeMsg(auth_resp_msg, auth_resp_src_node)

# AuthRespV4:
#   RandomPubkey:         22ee4da751006e7701442371ac5c0972414ca314a31aaf117d034c9cc0d9015eace02d3ce557c71e73a3a24b455a312647f09f6bcf20cc8fce850e5f9aeb9207
#   Nonce:                eb5140c05fa17edacd9c4eadda3179a2b433335d53e8d2888fc5591fcf95a3b0
#   Version:              4
#   RandomPrivKey:        2f1c59b5acabc39a92a1c6fe92d4efaf4c577331101122b6690051421391cebb
# print(f"{auth_resp_src} → {auth_resp_dst}", msg)
# print()

# bootnode → node3
src_handshake = auth_resp_src_node.peers.get(auth_resp_dst).handshakeState
# node3 → bootnode
dst_handshake = auth_resp_dst_node.peers.get(auth_resp_src).handshakeState
print("BOOTNODE")
print(f"{auth_resp_src} → {auth_resp_dst}", src_handshake)
print("NODE3")
print(f"{auth_resp_dst} → {auth_resp_src}", dst_handshake)
print()


print("Secrets")
# # bootnode → node3
src_secrets = auth_resp_src_node.peers.get(auth_resp_dst).secrets
# # node3 → bootnode
dst_secrets = auth_resp_dst_node.peers.get(auth_resp_src).secrets
print(f"{auth_resp_src} → {auth_resp_dst}", src_secrets)
print(f"{auth_resp_dst} → {auth_resp_src}", dst_secrets)
print()

# xors = xor(src_secrets.mac, src_handshake.respNonce)
# print("xors:", bytes_to_hex(xors))