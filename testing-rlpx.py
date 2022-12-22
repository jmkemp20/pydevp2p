#!/usr/bin/python
from pydevp2p.rlpx.node import Node
from pydevp2p.utils import hex_to_bytes

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
auth_init_src, auth_init_dst, auth_init_msg = ("10.1.1.10", "10.1.0.10", \
    "01b1042ea1e223c64ec90e93b325b263edc5027d967e4991f30d37bc5442cdec4448a6a1571085162855f7cbe7db8c984f83203c72de133f9377456a06a95087b97c029cd7ab3d8bb2bcc8ed5a91d7024d2e4bc07bf33dcde33333b63a443a54174b6b97bfdcd9a40e2c8a313d68b320ae34f4d963571ca9944a72e95fec4c1bfc0a78616160f0ae5f52ddff2c19bbfd87e5fa9cb1bfe2df709014890fde201881c8a6aaf19deb9c924f2e8518dc21f00d57cb710d68d78e2ad8ba97f256c3e05035676d7519cc0264ffd18a77d8559befa0d3b3d764e2df7df004649ce55fb1283837735defb370597482338239a6721a85008a258865369791a4741b2f84985448c58cda5908e77621350759d9eaa03e665a110c5556fdd5e7823a52f8ba93331ae2eb3fac454f8cb1264271564c2a68fd068314ab94cd885979dfa582e8945e02d47f19a6a2edda70e77cc704bbc0f389324b58204a3e64c6a186dcfe56cce87022a8c9e42d0530a7cb5e19a6aeb59c6fac715741f85eceb47e8f7c34240650fa133e3022d457788ee2922194179ae6172afad959c18fc52f3a9ada5c68e73c42d79951d6585b8cf7f29b3621207bcf8014")
auth_init_src_node, auth_init_dst_node = all_nodes.get(auth_init_src), all_nodes.get(auth_init_dst)
msg = auth_init_dst_node.readHandshakeMsg(auth_init_msg, auth_init_src_node)

############################################################
# AUTH RESP 10.1.0.10 → 10.1.1.10 (bootnode → node1) #
############################################################
auth_resp_src, auth_resp_dst, auth_resp_msg = ("10.1.0.10", "10.1.1.10", \
    "01940453947a726b2f35b397aa236eaac25afce8c9148fb3469df1ec311de274be434666ad496b63c32458d773661a054b388510cdd6507e63076af31e5fb13dc8df9a4b60378c6624c4d12d2f4ab52d1912b9d4c938122f598f32d94fbb73acc7880723daa048d943be6c9a3db2ce425d4b6ca96da95004170c43f231e4c7516306b3f1a764a39217ccca4cfa68159c9552534e196c23bfc557e450f26945066f485fe91f4a6fadf456fb34cd35ebbc319889214278cab5e6ed5db8e93593adeead931346ab0260a0524b7352581a909e97979950fb267a9db9073b52ac800de72c71e84407fc33c4712480f35c4a178cd3fa13c88169895de5d72d8b3c6cbc6446e9200db2d1c1ff7a565552cc5365d5b86496d1b45d95b85ad85242c47e0b89a870a68c25207604a79fff59a7ed18f6fc5107ceb0b10ce83f928be577f20144d33134d55d05cafc7e84c1d5be4bb559d9cdd6069f8a0409d5635dab874e5ee33e128448a515ec7bfce194f6eec61d5d7968111b29f54a8ddc73ea7bc3e6b3be24ab608f65f7c55cc73bf4c6d69de3f89bc991e743")
auth_resp_src_node, auth_resp_dst_node = all_nodes.get(auth_resp_src), all_nodes.get(auth_resp_dst)
msg = auth_resp_dst_node.readHandshakeMsg(auth_resp_msg, auth_resp_src_node)

# print(auth_resp_src_node.peers.get(auth_resp_dst))
# print(auth_resp_dst_node.peers.get(auth_resp_src))
# print()

############################################################
# RLPx Frame 10.1.0.10 → 10.1.1.10 (bootnode → node1)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.0.10", "10.1.1.10", \
    "e18258d052badaa3170864887d7e9bba642e04229526b6385c095d85f148740ccb3fc550c27be1302ab83255b26f17b1829bc61a6aeee39e069c5dbb644219500f9cb2676b69dbc2d90c10b015d62f6596cc17b0c12ca136734f66a0a9ac70853eabcc63c2c22bd1cb58af3a0c0886fc7fea05564426f788b67b4d135b534d002634af1dc40e590e2db31cb0a9cb6e2636ea67ff8a3b9b1992932b71e37fd227642c61e70250fcad6a567f7fc911095b6aa853001e9d653019ed69f6412a2befccc49395437b890f00d88328f5635e71")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

header, body = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(f"{rlpx_msg_src} → {rlpx_msg_dst}", body)

############################################################
# RLPx Frame 10.1.1.10 → 10.1.0.10 (node1 → bootnode)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.1.10", "10.1.0.10", \
    "e18258d052badaa3170864887d7e9bbafcdbe94242a818ece572dcf30f8edd88cb3fc550c27be1302ab83255b26f17b1829bc61a6aeee39e069c5dbb644219500f9cb2676b69dbc2d90c10b015d62f6596cc17b0c12ca136734f66a0a9ac70853eabcc63c2c22bd1cb58af3a0c0886fc7fea05564426f788b67b4d135b534def3177d860a529f441fe4ddfdd5e0b1e1b76024b3a17696ecc339958213f31ca19967a3b3ffaab0a47cc0335eaf9ee371b13c933a878155eb89d47fd8a4e2341ef2d0d830aae3728776ba63bb92a99b45c")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

header, body = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(f"{rlpx_msg_src} → {rlpx_msg_dst}", body)

############################################################
# RLPx Frame 10.1.1.10 → 10.1.0.10 (node1 → bootnode)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.1.10", "10.1.0.10", \
    "ed70edb8d85333712d39d2dc9f3958ec5aa8ae80a8bd615ffa28cda86af3d9122f7744fefdf38c1d85aada754f52159a12b3e185bec18ed5c113f7aa5c8f64cceb082573296d5008bcc231adcc584741d9672bf0474f27d4c5a241c14ea2b36b27639db84b776ea4ad3d0ef18a66f2ad")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

header, body = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(f"{rlpx_msg_src} → {rlpx_msg_dst}", body)

############################################################
# RLPx Frame 10.1.0.10 → 10.1.1.10 (bootnode → node1)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.0.10", "10.1.1.10", \
    "ed70edb8d85333712d39d2dc9f3958ec83312c3d7e064f6e50f71a1b29974a212f7744fefdf38c1d85aada754f52159a12b3e185bec18ed5c113f7aa5c8f64cceb082573296d5008bcc231adcc584741d9672bf0474f27d4c5a241c14ea2b36ba7ef4617e39193c266b668683306d98e")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

header, body = dst_node.readRLPxMsg(hex_to_bytes(rlpx_msg), src_node)
print(f"{rlpx_msg_src} → {rlpx_msg_dst}", body)


############################################################


############################################################
# AUTH INIT 10.1.2.20 → 10.1.0.10 (node2 → bootnode) #
############################################################
auth_init_src, auth_init_dst, auth_init_msg = ("10.1.2.20", "10.1.0.10", \
    "01b1041b6c151e2041b78509bd9c368a86dd254455d487b95c34b0a89fc3c8ceb289f173bb786eabb980ad9766f290b11a551fd124e45b5ec74b774d60c10741772a95d30d4ffbedd58b0779b236ffead0b9d6e12ebe41a36b64b45e199c493d34aa83455fcc365ff7a2d6cd109de0b61774d7248d4171695421b5117ab9a44f76b4fdf14601ef32d289193020582c84602cbba99d0a02c89b807d17c1b7096648df6475805915ab4eeb55ba7febcc3d80eeb6b610b4c6617f50e2b9ef8aed681ebaac598aacc69162aa5d0c902840c5182d401b832e4ad972952f08936eae9b16de370484fda981fa21d43704155f82c840c2d37922978507439f116197ef4c19cdf0fd6e847eb1fcf5da839e9cd2c2913bae482f3e55cebed2119a98915c089df3c77381102cbe9493a5e7e4987e7772ebe6edb1fcd39aebea50ecd85ef104b0b68d10156a6bae76dd56e8b55b12b7e2c95b5c441a5ff6d286298446930f45a8109ffe41bfddbc1645256569ceb2047e0381e7ba16cf1dcc7db005871ecc7f7c1e48c4435a37c9babf73c2078430b352471c3287ea75cb05552319037567d62900649ae3c8161d9011f8c76e438d0e79ddda")
auth_init_src_node, auth_init_dst_node = all_nodes.get(auth_init_src), all_nodes.get(auth_init_dst)
msg = auth_init_dst_node.readHandshakeMsg(auth_init_msg, auth_init_src_node)

############################################################
# AUTH RESP 10.1.0.10 → 10.1.2.20 (bootnode → node2) #
############################################################
auth_resp_src, auth_resp_dst, auth_resp_msg = ("10.1.0.10", "10.1.2.20", \
    "015c043aaab967dc5db5e0c8e6fff9fe820f4f7d94ceb48bde654e732924e4bd6d6d8edc73c900ce5b02c96f5bb5520fbe3e64d2282bb48000aeb21f4f4166087442ad1531c81a1dc4db16a4b707f2b3e46494a16fccb6b04930c87711231eba5eb2d21d25d8f092d004d05fdd89c426502e4ac9f82966853449b21ce83b27dbfb3f3d3570cc60c703e64dcc93af6d9e2011484188403f53e6fcc5d37384077011c1f0ecc93678af63926a1736200342c9deaf31741c5d8a3dbf5e1d031c7bf30fff1645b7684a4774220929eb713769e8b0ca1e85000c0d46c14ae76fcc15baa5fb83708d315251997c7be69d32eb42ce207abdb0293e561256dc9505565c2645d205aa8eb2da246ae8c1603bcbbefa1bf8f80c97de8ff16f54e6c0ea73f3d58d9e4e707a33ae798cebbb53973b051857435fa213848fd3eb47ada252c0d4135665e824961ee7d3dcb8f6b3942733b392487456d1a4c7d355705ef7dea3")
auth_resp_src_node, auth_resp_dst_node = all_nodes.get(auth_resp_src), all_nodes.get(auth_resp_dst)
msg = auth_resp_dst_node.readHandshakeMsg(auth_resp_msg, auth_resp_src_node)

# print(auth_resp_src_node.peers.get(auth_resp_dst))
# print(auth_resp_dst_node.peers.get(auth_resp_src))
# print()

############################################################
# RLPx Frame 10.1.0.10 → 10.1.2.20 (bootnode → node2)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.0.10", "10.1.2.20", \
    "169b0ebeac3f711c8dd62533efc778a5a1f00d16eba288a445b784d1d36d022c955e2d8eff354e48a79acdddade16b573c929d9b575dbdd0630a7b83635d6b1def6acb1f10f96be7fc3ba075d264c1d3b62a3e7b7be0f5a2f257df23819aa92e38d4bbe671e4b68eb994652d3de685057b928660e4ca5f812afa9234d6db005bc1ed89098143b1de589b3d0092617b749b993a2c348754779af990cff0fdf10f3eb59f663fc395be9e8f577dc50c805bbbd5602fbddc9c56063727c873b89aa3b5c69512c310850c22f01ce7f752058d")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)

header, body  = dst_node.readRLPxMsg(rlpx_msg, src_node)
print(f"{rlpx_msg_src} → {rlpx_msg_dst}")
print(header)
print(body)

############################################################
# RLPx Frame 10.1.2.20 → 10.1.0.10 (node2 → bootnode)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.2.20", "10.1.0.10", \
    "169b0ebeac3f711c8dd62533efc778a5c2cfb8ac16ab8850c9e5e0b661f9daff955e2d8eff354e48a79acdddade16b573c929d9b575dbdd0630a7b83635d6b1def6acb1f10f96be7fc3ba075d264c1d3b62a3e7b7be0f5a2f257df23819aa92e38d4bbe671e4b68eb994652d3de685057b928660e4ca5f812afa9234d6db006d6c0f585cb98578490fb58c04e93b36f76dce68ab2928148faa61948437ae886dca8eba9d431ab3527dc2dcd22b35f0f439784134dce9561ae12579c3399cbba386aea1ab8de29a6daaf64feafc42ccc4")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)
header, body = dst_node.readRLPxMsg(rlpx_msg, src_node)
print()
print(f"{rlpx_msg_src} → {rlpx_msg_dst}")
print(header)
print(body)

############################################################
# RLPx Frame 10.1.0.10 → 10.1.2.20 (bootnode → node2)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.0.10", "10.1.2.20", \
    "e526bdaa7bd28ded597a034eb78777aa86b3e6cdb4722c1455c636528fdc9f9e8cd963d78da339573780990768e85f942657b79c1b3730a878108b71dd6c1859beff913c59dc9dd2848c94656a244766c378f9c5e52ae4cc2abd7b5885d0e8a32ec494aa8a59bc49b1b6501e89381d95")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)
header, body  = dst_node.readRLPxMsg(rlpx_msg, src_node)
print()
print(f"{rlpx_msg_src} → {rlpx_msg_dst}")
print(header)
print(body)

############################################################
# RLPx Frame 10.1.2.20 → 10.1.0.10 (node2 → bootnode)      #
############################################################
rlpx_msg_src, rlpx_msg_dst, rlpx_msg = ("10.1.2.20", "10.1.0.10", \
    "e526bdaa7bd28ded597a034eb78777aa91d4b153a1539b2434f215d34272d3d18cd963d78da339573780990768e85f942657b79c1b3730a878108b71dd6c1859beff913c59dc9dd2848c94656a244766c378f9c5e52ae4cc2abd7b5885d0e8a3c13b8d3c7c737bf68c1fc814722441c0")
src_node, dst_node = all_nodes.get(rlpx_msg_src), all_nodes.get(rlpx_msg_dst)
header, body  = dst_node.readRLPxMsg(rlpx_msg, src_node)
print()
print(f"{rlpx_msg_src} → {rlpx_msg_dst}")
print(header)
print(body)
