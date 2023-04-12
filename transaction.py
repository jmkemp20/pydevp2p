#!/usr/bin/python


from pydevp2p.crypto.utils import keccak256Hash
from pydevp2p.elliptic.curve import decode_pubkey, ecdsa_raw_recover, encode_pubkey, get_pubkey_format, privkey_to_pubkey
from pydevp2p.utils import bytes_to_hex, hex_to_bytes


msg_hash = hex_to_bytes(
    "75cc828f236e030954b1b589cfede496baf5ca58c33c8c2553626907bbd38c9a")

v = 24726
r = 67255722872072334048399793730552662219602420979885419241564245918823877753345
s = 1901596662005870942390440947845587422286998131101601821002684730848161025480

Q = ecdsa_raw_recover(msg_hash, (r, s, v))

print(bytes_to_hex(Q))

pubk = "86864f6ed98074210277ff575b6970e6b240066795cc5eab1909dfaad3b87aa6ff73581ce48c2b3efc07d41789db6cc6142e85bab93bc57415f5086228e9057e"
address1 = "41159606b6240f725e969e3f1f342ff65904a4ec"

pubk_address = keccak256Hash(Q)
# get last 20 bytes from pubk_address


print(bytes_to_hex(pubk_address))


boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"

print(bytes_to_hex(privkey_to_pubkey(hex_to_bytes(node1_priv_static_k))))

node1_pubk = privkey_to_pubkey(hex_to_bytes(node1_priv_static_k))
print(bytes_to_hex(keccak256Hash(node1_pubk)))
