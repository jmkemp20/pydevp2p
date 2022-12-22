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

###########################################################
# discv5 UNKNOWN 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###########################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("b6eebd128ceb6ecce8be7bf9818d835004b9e96c93c93062b81844c56a13cbb3c50ceac7cee754b3356168c15daf5b17d4a711b4a646943c673f9606844d40a27f82e7c4eb88c5a028f9a8903e96bbfef35f4e38bd54d49a5ab0cf"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
# if msg is not None:
#     header, packet = msg 
#     print(f"{msg_src} → {msg_dst}")
#     print(header)
#     print(packet)
# print()

#############################################################
# discv5 WHOAREYOU 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#############################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("0f315986ae709d080bf18bff90341cdd429e2b7691d250fc6a6b580d9a33dabe4ff6c899703aaa2ac24487d7b76c138a51082a292c563747cc98fdd6ee308c"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("50cabdd48f9abef8a1babdb0395b2a537e02531695949b3b159ab823c896bd83becfea34986e615fd3cbcae0c492394fda5bb39ba3f23a54a027bf85a14b345a42aec4a09419f05ff69ebed1e89b2cc64accddd9e2d6544d6d1aaad474b6829e886a015d4557307c7c055b35b571d14dd6eea90afa4a9cf6f8aa190b0e4a83bc320eddf3c5d2b9dbc019a7ea995a439fe8b0652965e141d45d57dd4af5ac74d7197724bc3c42e5229d01fc01d6f70253e894c351b3ddab2476d191050dbac9937e8546025796d28d1deb3c95a7356e269e8c85f16843857a3600fff24346a2a350755720f1e6ca3bb2ee27c7c2a136632fa730eae12842fe951344051a583fbf57644f3dd2513ab97e62ab4a827522c54775a8f0ad53b4184251849776599352574daaa1d0c16d978640db56c019adbd57f93a7a8f88054bc32e3d6f02cedb0f76d43cc0c2b53bfc2b5a782311fdee38e1a9d4691fe619f05d9655a348b5af5ae2f9613bba819469bcb231ae815e388678ed"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
###################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("e505a67f267cab581e857ca5ed063a7f7502c8124fc540c0a28c3ebb0bcb84d924f3a52c2f8a79a959f147dde56178c1f1a4ff1b3228da28bd4d2d51c0c05be4b4baf0abcab619ff7ccf7cb7452ba0a314801bfe80c4bef6bb0db18d314efec31c62ef97c6d58160b12d59c2dfdedfbb4574ffc88c3d430c0da90f91579d0763bfe7ebe48306782adb7167a7028671c8e4fc9fb923f3afaf8a4d669cc2bdf8cc351dab29e1072888572a1f9141bff55c5b5efdf0d5db2aab64b1cb5c14471e7feb6fc5827ffad5e2bc112441ff309e102b0aa8cf18b6b28e58853609a2e627eba5775302f862a180490acd84652b61acfa504fc71b943ee00c3a3ca65e43492cbca6828de2a292e1e43bd5"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("3e860358ee113fb354f9b39853907a58f9369fb63214cd5136285857ffaf19309c7875498fc37552d831b781cb79a03944271e055d043fb650acdcfc0ad2c84e0e45df352b29e3e1a26ea4f85721817c1b85d07abe7b2cbd8c7463daa416e83c13a475d64bf45941ca58"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
###################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("e01aca1e777904d5c16ebf3a82dfad96d114b12a65ffb6bd62598d70e15e1a608e777e05ef3ce17b0449c0d4c4b752560c94b2849a0bcefef3f23af7eff0ee044f5c052ddbb882d761bc12e79e71f85d30c98c02a785d1f356a997775f5623a12d232c2c0ed72422ca7c9bee17934b0fbec069a2eb404ca28f8eab35f1517be56c4c9c4a2486f9b3be4f4bdfecd6be260459b293bfe09b88b58d57a4460b122b6e4dbbe21431cfd3491c22fdfd8b6e3c3500381e63e9a81ed31947ec206d59e0ab5eceaf0f3a37c9db36fb27e20b00db045719fb02b160721a60f47958058455ac6a3b33a1001a3e76fda492fc1801e7b0c332bfa1367487b863fe4a20338461dbe5ffdeaf2b9a4d8d7c1d"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("bd45634dc3194ecc19660ce04abc6b9103807456d6bfa5bff845d072cf2f7e08bc5fb76ed3d1477cea7cb6c081f78790f11e59ea6ffeb40bb0c069a3d5ec581db49385a8e96c63aa85a52c7af9dd85939ed56ba98912252e09cf003b16888f4abab6ffc4d4a1d35a9a33"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
###################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("2513a3bc22ba33eb3f779cab1a1763e8c9540429639579fa8caca21492d00815d1c970cbdcb23d5ac3d697c5ea45c7ca7e2b2209488d45dd8ff8b0c4682b333029d58b0516e5074a171e8cd7fab5e860000d3b1b39d31f335bde61fef22111887775dfca842494718711c6947d6efe3ac876095190f8b9241cdb5a2f4e827705971842406e4702222465bed8c30866050a6ddf4f14d94f084c610004ec92e369883b40ffa725461cb1709156fd24be1da3994ff48eb12c565e9201ae58dfc2566b6a624fd6b7af7a1932108ebed613625497d104082bf0ae0291c31d12168d246863fea0228d52be3dbdb69194271c4932008625e82f3653aad3fc97f20b2f685a89a61a1e9e488e2f3651"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("eebf1c28bc215eb748e64eae8d8be00bebaf7d0c3f63e9be47fb32e2879b1a1b514d2d9fa18ee94422dc425b9f0b09e3dd7e03f626a1fb2a380bb0cdca6055c92c1549fe331d312f7e4fc22930a3b78332431b78ee7dff6e6604ca200eccd398e472341ccee34d015ce8"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
###################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("c179a3263aa9566128126bdaf7504a75d0ffb93b80a2dd87bab8bfd9a052c62b308853063a732b9a10ae11c89830a1703cd32e2e498805d9cb1f9601bc60e3052d310017f946b66104404f842506c48476c10b5106d5934e48bd353d705df1ff79ab13d4a9cd1baabdac752e0b35ece7574e9434cd5f5b6c9d05a07d7cc780e5f71cc12118467aec4abf6540e536643738fa0600dc143303936f5d8de545ac1a132d30c6fc951dc81ff05d7c99afbdeb0eeca2be5f8d2ac086e1494198f2d4f73cc7de41c2c69872351530909481fbf5fe2d32996385b103435938a589270f502feca95c144be87d882acd6bea9eac6ed04456e786328848c72e60fa301c21af0bf8ba732c554979de9131"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("91dc0840481379c73de078ae97e87dad927f2f68ed33998f27ee95039b1640e5027d740883915669bed4a077209bf11c424b7268db086b36ef25b53f70883915f36712b0cfcf1b98b6adf9eabd40c83038bf2c561e6f18fa5f26dac09c9b5d3bcca6c4942594ddd9b6"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("9ff4c1e15ec57ec431eead9946d83904ede5f605d279f3cc825705be5f2a68f6fe1ccb3d9da4a0a79bd73d174d4125208d08da59de966409e86c64ad7676872669b7a67ad14732c09b8423396642f94464de352bc9444b5720d0c029c5527595eca79119"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
###################################################
msg_src, msg_dst, msg = ("10.1.0.10", "10.1.1.10", \
    hex_to_bytes("2621dc205cde63dddfe52a367c42039c1164513d420150a822360c8ffa615371663614ead5779d549c8f25211f068540149991bc83468ca244d2563b4d45716f56645feff6b896b0064d1b693cbbd381349801a9ec5bb5e19657c3ad29e0e6a12b0840a74a4874cc15"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()

###################################################
# discv5 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
###################################################
msg_src, msg_dst, msg = ("10.1.1.10", "10.1.0.10", \
    hex_to_bytes("d366152a340882f846019138c44a671cddb00b32c90b9722ce45b464b30d1d94d2fd6f303871c0eaa3ef2b3f1329e891c8d4060fd72452de7c41030f1c3a038619aa99d0cf89125c92e3a309c4fe11287f5992d83cda33a19355b23419d7af12a3fcea29eb65664c21063ae7ee73fe937b"))
src_node, dst_node = all_nodes.get(msg_src), all_nodes.get(msg_dst)
msg = dst_node.readDiscv5Msg(msg, src_node)
if msg is not None:
    header, packet = msg 
    print(f"{msg_src} → {msg_dst}")
    print(header)
    print(packet)
print()