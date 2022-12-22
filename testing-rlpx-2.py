#!/usr/bin/python
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

######################################################
# AUTH INIT 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
######################################################
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "01b1042ea1e223c64ec90e93b325b263edc5027d967e4991f30d37bc5442cdec4448a6a1571085162855f7cbe7db8c984f83203c72de133f9377456a06a95087b97c029cd7ab3d8bb2bcc8ed5a91d7024d2e4bc07bf33dcde33333b63a443a54174b6b97bfdcd9a40e2c8a313d68b320ae34f4d963571ca9944a72e95fec4c1bfc0a78616160f0ae5f52ddff2c19bbfd87e5fa9cb1bfe2df709014890fde201881c8a6aaf19deb9c924f2e8518dc21f00d57cb710d68d78e2ad8ba97f256c3e05035676d7519cc0264ffd18a77d8559befa0d3b3d764e2df7df004649ce55fb1283837735defb370597482338239a6721a85008a258865369791a4741b2f84985448c58cda5908e77621350759d9eaa03e665a110c5556fdd5e7823a52f8ba93331ae2eb3fac454f8cb1264271564c2a68fd068314ab94cd885979dfa582e8945e02d47f19a6a2edda70e77cc704bbc0f389324b58204a3e64c6a186dcfe56cce87022a8c9e42d0530a7cb5e19a6aeb59c6fac715741f85eceb47e8f7c34240650fa133e3022d457788ee2922194179ae6172afad959c18fc52f3a9ada5c68e73c42d79951d6585b8cf7f29b3621207bcf8014")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readHandshakeMsg(msg, src_node)
if msg is not None:
    print(f"AUTH INIT {src_ip} → {dst_ip}")
    print(msg)
print()

sleep(.2)


######################################################
# AUTH RESP 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
######################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "01940453947a726b2f35b397aa236eaac25afce8c9148fb3469df1ec311de274be434666ad496b63c32458d773661a054b388510cdd6507e63076af31e5fb13dc8df9a4b60378c6624c4d12d2f4ab52d1912b9d4c938122f598f32d94fbb73acc7880723daa048d943be6c9a3db2ce425d4b6ca96da95004170c43f231e4c7516306b3f1a764a39217ccca4cfa68159c9552534e196c23bfc557e450f26945066f485fe91f4a6fadf456fb34cd35ebbc319889214278cab5e6ed5db8e93593adeead931346ab0260a0524b7352581a909e97979950fb267a9db9073b52ac800de72c71e84407fc33c4712480f35c4a178cd3fa13c88169895de5d72d8b3c6cbc6446e9200db2d1c1ff7a565552cc5365d5b86496d1b45d95b85ad85242c47e0b89a870a68c25207604a79fff59a7ed18f6fc5107ceb0b10ce83f928be577f20144d33134d55d05cafc7e84c1d5be4bb559d9cdd6069f8a0409d5635dab874e5ee33e128448a515ec7bfce194f6eec61d5d7968111b29f54a8ddc73ea7bc3e6b3be24ab608f65f7c55cc73bf4c6d69de3f89bc991e743")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readHandshakeMsg(msg, src_node)
if msg is not None:
    print(f"AUTH ACK {src_ip} → {dst_ip}")
    print(msg)
print()

sleep(.2)


#######################################################
# P2P HELLO 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#######################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "e18258d052badaa3170864887d7e9bba642e04229526b6385c095d85f148740ccb3fc550c27be1302ab83255b26f17b1829bc61a6aeee39e069c5dbb644219500f9cb2676b69dbc2d90c10b015d62f6596cc17b0c12ca136734f66a0a9ac70853eabcc63c2c22bd1cb58af3a0c0886fc7fea05564426f788b67b4d135b534d002634af1dc40e590e2db31cb0a9cb6e2636ea67ff8a3b9b1992932b71e37fd227642c61e70250fcad6a567f7fc911095b6aa853001e9d653019ed69f6412a2befccc49395437b890f00d88328f5635e71")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"P2P Hello {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

sleep(.2)


#######################################################
# P2P HELLO 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#######################################################
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "e18258d052badaa3170864887d7e9bbafcdbe94242a818ece572dcf30f8edd88cb3fc550c27be1302ab83255b26f17b1829bc61a6aeee39e069c5dbb644219500f9cb2676b69dbc2d90c10b015d62f6596cc17b0c12ca136734f66a0a9ac70853eabcc63c2c22bd1cb58af3a0c0886fc7fea05564426f788b67b4d135b534def3177d860a529f441fe4ddfdd5e0b1e1b76024b3a17696ecc339958213f31ca19967a3b3ffaab0a47cc0335eaf9ee371b13c933a878155eb89d47fd8a4e2341ef2d0d830aae3728776ba63bb92a99b45c")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"P2P Hello {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

sleep(.2)


#########################################################
# ETH Status 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#########################################################
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "ed70edb8d85333712d39d2dc9f3958ec5aa8ae80a8bd615ffa28cda86af3d9122f7744fefdf38c1d85aada754f52159a12b3e185bec18ed5c113f7aa5c8f64cceb082573296d5008bcc231adcc584741d9672bf0474f27d4c5a241c14ea2b36b27639db84b776ea4ad3d0ef18a66f2ad")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"ETH Status {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

sleep(.2)


#########################################################
# ETH Status 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#########################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "ed70edb8d85333712d39d2dc9f3958ec83312c3d7e064f6e50f71a1b29974a212f7744fefdf38c1d85aada754f52159a12b3e185bec18ed5c113f7aa5c8f64cceb082573296d5008bcc231adcc584741d9672bf0474f27d4c5a241c14ea2b36ba7ef4617e39193c266b668683306d98e")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"ETH Status {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

sleep(.2)

#########################################################
# P2P Ping 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#########################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "43ad0ea564913ca9676d4e8ad9a63ffc85c1a89c8e34affff8fc1fea5243e371f61a461e6942c68a445d31add137a966816bea05422ad7dad8c1237ad840c3c2")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"P2P Pong {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

# P2P Ping 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "43ad0ea564913ca9676d4e8ad9a63ffc330601a97ebff569718c3bbb32fdf692f61a461e6942c68a445d31add137a966deb48fb19589e2240545c3dcbcd293cc")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

#########################################################
# P2P Pong 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#########################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "37a17d60de3b37871a98b90e2c56cb42ee69b03f2902ec712a186d73a76522d700f9caa63caaa4a78a890382d202daf72e83e77725555046abe33db71ab6f701")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"P2P Pong {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

# NOTE
# P2P Pong 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "37a17d60de3b37871a98b90e2c56cb42840ce9a16157c2091f533cbd51cab32700f9caa63caaa4a78a890382d202daf748cb6641d9ee3e26251507648bb7c072")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

# P2P Ping 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "c3aa7bea997f9d3d4937fda7d954a3d8de13ed1fa627efc6ca9a06680ba9a009713055f1229cd7dfc7204be9db7ded81f778e8657a0aa0c06b492531cb3dfdc3")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

# P2P Pong 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "c3aa7bea997f9d3d4937fda7d954a3d899dfed7f151a8f8300a19590a163fd01703055f1229cd7dfc7204be9db7ded816f1bbb0980f9b4e577d9b1d04edc40a4")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

# P2P Ping 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "3bdc0e236a1d2dd6929bf5e200b160ce1bf7e85e46c47a9ebf7ed84932d8d1e447b3a55417e2c3cc1d4fe0e96faf1eb7ce1ec074387c920aa26f1e3e94e7ffa6")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

# P2P Pong 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "3bdc0e236a1d2dd6929bf5e200b160ceb4c15a7614ccad32b4b53e9f0bca951e46b3a55417e2c3cc1d4fe0e96faf1eb7da762fa7bcf1ea4564c2694f798ea987")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

#########################################################
# ETH NewBlock 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#########################################################
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "82502a17858f44c2c668a3f65316bb9f424aef51e98f64e566d42809e993d6bf075d61e9f901fd78b3eedbfe66e098e0e29f7d364b1b28c048298dc8b7aa60f02cd65c13e77f44365d6b1527d5f09a079e7d231f32fd7c564e15ed87bc96c098574662ae390c11d337cbd7324d10bbb1c75c4435e9919538ca7d6e669f907b5443aeec702e0e01e4c49bd027ef67524c37f7befb346a9ebc6909daa0617a8e878aa15f13e12ad83e3802871e7c1e5c999669fb83cb6a7178f7511e34a511c48b4fae70f475e554752ef88c04e2b8d95f8980db355b01cfd671f3437cabab1417c3007cd12547a0081fd9a0f388a84625ff02c78f6057efff9561449ea7ab43d99d411952130a91ee458f074eeb45c0635053759dd0d01c362be9068e13849476847339c7e22c6929276f414e3d1a174d7c8943dd365d0b488123bffa3240699c12c21cf5a72dc5e641f16b26a9aaba4be7da745a0be0e358167e7b638304b4b7")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"ETH NewBlock {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

# ETH NewBlock 10.1.1.10 → 10.1.0.10 (node1 → bootnode)
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "dcb70642a5ba2670e4f416a671c589470a89ecdcf39b24433104b3122e49284c860c0713455b38c77806b3a0fbb152950851547c456b2312d9e0266fd1c6708eeae8ae8e3c55ed4415212a03e07598ca812fe90bbe064256c5a0321971de7ee7b3af34a0e1205adf1ae9731d676a2060aab7801f42f6f6beee5f1318fdaf6c2965cb813e595d559b5fe37ede177efe24b70ef2371e64c443906a93d28018ffc98f374c7b86c5ccb3c2d0ac06360595b9073cc80123f87553b0ea3df4aebe867908676df054a9ba775a1d77e9f63dcb6b0c3e0d52c7ff2717a1b6da8bb0fb9afacc94decf54153a0e0ebbfafadc00f12ab02c17b56daf28b1c72957d6d6aff1e473a1dd4c0505d6f61e9c7c1b3577f7f1f864f5bdd115990a21dc4c295ef5bf2b980841a498c947156eeacf61c799a01916cd0cccfe7ac32d946570d8600cbe441863a9562ecaba9b8a590c69258381c3be484c552226b72d453c8812dc73d5aa")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

#########################################################
# ETH GetBlockHeaders 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#########################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "82513217858f44c2c668a3f65316bb9f7d2b26c57a436c627f716dcb458fd0ec03edddf7c790da3ee5792741431498478137d5ecc8abd1d366e4c7557231cae78d09c60a928cb7e4ac5efeefc2a0dba5bcb06ef7ec3a212ce59058e00a5a1482d18015d51c752cb6d062283a65bcbe32")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"ETH GetBlockHeaders {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

#############################################################
# ETH BlockHeaders 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#############################################################
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "e736395304ddbc709211316294d58cb01cd9d38b75806024dee58001f6c1ab38e2fc48cc065e0a82f281e86699e2f316d087e40a1246a8b24e57df61ad95b397b6815d0d067e047104392d012118d34bc3b489ef0ede1eb0d5ecaff6f8a4fd2b550300ec7ce210216ff47d6af3a17f8934cf7ff8eb11f8e604641ef37e3747691f7ccfced209c30c3bab5da18f2701a2ac6dfcd2c4de44919bcd57f32c4b043d87f40adff96bb39b1ef2eb059836a08bfe95a6519dcd05b970809f0ee98da09521af1f67eecc6bae5d161b9592b31fbcef949b6729fb84fc50a39fa170555bf57f3464b8bb260edc3eb5111166f1798bd280e2ed2d188e4c061a1a937e6dbae4a8492b33edca69aa495375383c3562617ea866dc4702d3dcb9f2de5e33627a5b8b1ecf0fcc30f5112526dd884881ee3ab26d47628d844d4bd615c8e862c66429c4da5652063ae7adc81687428e7bc8725c3135a4662035872796ae2353b9f1ea")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"ETH BlockHeaders {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

# ETH GetBlockHeaders 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "845435772d0665c0c76a95cf0dc428f6d247d78ca39dd0018e3799624414d6a040f9bc21ba9858b01ccde43745ef4f3491b61aa815ae6b158dcd6ee47150529a5a9136664402e2b4ada0fb3d58085821")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

# ETH BlockHeaders 10.1.1.10 → 10.1.0.10 (node1 → bootnode)
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "647317e9e3e85e71275a10cd42750b628ee247ab6c56b599d94bf11711e5765adb0696a428fa15a15a0a8e217e6da07354b70caebac77ea2c5c2b607211ecd5075deb5666cd2bc2d5e2fa2979e5277a7d9ab8b8cb653612e2c313e80ff5948630e03c61b715025b7051d81173a7dffcca0d056dee894cbfe5a17bf2fac646bbf19c58337c4eff41f7125ec22bb3ed6da0c76518a23cc9318d8011ce864dd1af76aac299cbf406fec8e17f6c4fe55189623b0ab205d80e23883bf47066d124ed9a6d63565bbffd78db3a720c63084c5b19fc6a0768eee151889d60d7bc860370a99c747aa711dfd4ed48bbe81657750c98277f05791cd9f61f81a43dcfdb90b5710ce26381c0fcaa74051cdfb33b69d61f077a68e2f260c07c1aa75dfe82a0f7c143da1c0ae8afaf484e3a74be8950b2ce4d960b9743ac27974e128b5f6403ad96db76d907ab531414866dc552948ebf149aa6d9de6a8f1bed6e6d838676d706bf3a047449499de5600c2af6cf5699effabe0aa0a8da97081219f4c1c6c98759a14a95c7065969a362c22dc228307b982")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

# ETH GetBlockHeaders 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "3b32967c6e729025b4db0d3ec720c68f3eebf3c26495454fd68df58db6313f3abe096f6693c2c137219e5474648c7ba694ac9cae8b921f23bfb105adc9bc048a3889553656330550a8096d94df75120a")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)

#################################################################
# SNAP GetAccountRange 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
#################################################################
src_ip, dst_ip, msg = ("10.1.0.10", "10.1.1.10",
                       "2d8184d596d175d578109313f9748cf9db8c8b7eb45e31d3c7e56410aeef9e3d5771262bb9491f0e0be3dfd42881b449921e6b34e812f8f69c624761b651288eef61de160cfbac84c7cd71f9a76ecc710499ec511802b586df8d6ec680a9f04d616b5bac55bc75585e91a6f6c6c173fb19bdcf2279f97d0b4d42e6814c635bfe")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"SNAP GetAccountRange {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()

#############################################################
# SNAP AccountRange 10.1.1.10 → 10.1.0.10 (node1 → bootnode) #
#############################################################
src_ip, dst_ip, msg = ("10.1.1.10", "10.1.0.10",
                       "4c6056626a71ff8acfc98b610084894dd9793165292065ad34e4d79703e7b0a477331156651289019ddc4b5cc1945214f8b4da90830cab5ac776c5d4100946aa")
src_node, dst_node = all_nodes.get(src_ip), all_nodes.get(dst_ip)
msg = dst_node.readRLPxMsg(msg, src_node)
if msg is not None:
    print(f"SNAP AccountRange {src_ip} → {dst_ip}")
    header, packet = msg
    print(header)
    print(packet)
print()
