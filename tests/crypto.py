from hashlib import sha256

from pydevp2p.crypto.ecies import concatKDF
from pydevp2p.rlpx.rlpx import read_handshake_msg


def TestKDF():
    test_input = "input".encode()
    # used to test actual input
    # test_input = bytes.fromhex("e26928fc80fc0ce5a562a032a72fcf6ace7a943a82ac464efc9a9dc58eba40b1")
    tests = [
        [6, bytes.fromhex("858b192fa2ed")],
		[32, bytes.fromhex("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0")],
		[48, bytes.fromhex("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955")],
		[64, bytes.fromhex("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955f3467fd6672cce1024c5b1effccc0f61")],
        # [64, bytes.fromhex("994747c75d2e887ba139cb552c23ced97f1679cadbc54784a4bda8040767ee1ac25fa9dcafa07c5784816090aacdaa23ff8e99075cced1eea25e1ca84fa2766d")]
    ]
    
    for test in tests:
        length, desired_output = test
        print(length, desired_output)
        hash = sha256.new()
        actual_output = concatKDF(hash, test_input, "".encode(), length)
        if actual_output != desired_output:
            print("TestKDF(): [FAILED]:", actual_output)
        else:
            print("TestKDF(): [PASSED]:", actual_output)
            # print(hex(bytes_to_int(actual_output)))
            
def TestDecrypt():
    # The private keys of each of the GETH nodes, found in ~/.ethereum/geth/nodekey
    boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
    node2_priv_static_k ="816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"

    test_auth_msg_c = bytes.fromhex("019004195b7107a1d7a067ec2ccf17062d07191bf34d05557853999557766d1ee02c131fb6d00adadb833dbf794777ea0b85635b7f65fe0961e39877e6e4f35a161726cb988e62f9d674601360f35b04973edf04b9bd8d9db3ad7fa23c0e189f7d6d847de4ac9a4e444492185a3e0347a5b9475c5e8f4271846b7e5ece9da1f45437ef6768a85584b63821337ecb5097fdb6dd4ac6001d7cc05efd1386cfe6c0ea7259151a7cc275a2c3926408db21cc8961c9bd55b1601cff3bfae04e954448a36b69c2b606685ba44455601538e991693ae977549c71cd7e4eee3bc24cf6e7a7836b49ee3c31aed41a1c624f03d8d53ca0b0bf9c36741e4e6095184749ef5aea3e7e5d36d27ff6e1a9beed2ef30cf1fb2dd6028b803a530950e1cd2799a4f8494ffe7ee15efd06bdaf2d34316325cb55c80918b46ed94364ce91288ec3a541c1f0f42441895644c1b5f70ebfa31dd0eee312f7e8e1dc819f2035ef916e33275ffa8544177eec40e4fe1c3544c74c76d0da6f79d997282889fbfbefde531146a51460da8b0a32488b23af706c0ee002eb4d")
    text_ack_msg_c = bytes.fromhex("019904084dc15ee4efbe60965cdc07cdd21a9a7a177d5568e1567c8f6f24943c3ab7b235be23b8234f7b494fa1134c332ffba5c39fba588b440041c6ced2eb6069d115dfba3b30d66e88a621f16663208f567ec1033015cb7f750d10aa70c109cce839eee6b2e2ee4ae3163773ecc1e72ea2c2b18500bfeef7c21cdb821480da7d7b34d4d62a31ecb81d92f62af1e35d31d3ba7935591979d6092ea23a38d86e1a60eefef17731e3c0cfd512f2cffa9c794d882c9ff4a18da7a4f4490467a6f3e7fd44cea921c870c7230d93bfcef656f24423fe3bb2267a00a0f03a782a7d431c25bbbed8ac982e0862866b7a2966d22137a8c1b60969ec92c416375eece54733778042ed5e6a8f3a63390793b70f50b4a6e32810d154bc6711aa5aa6d69256edf14b9817fabd6811af8afb6065bd6bd2f4845b0ada2434047636ba04eb49bc17b09414f672318196bfbe8c17b67419d4c3acd52ca3765f067648362b63b2e3c7e8a52503b21b3b46bdff159e05c9668dcf162afc5805310d816560a74c73ad0ababe33de259c5dcc1c6863e3c8c5936265385b5453757ff78792")
    dec_auth_msg = read_handshake_msg(boot_priv_static_k, test_auth_msg_c)
    dec_ack_msg = read_handshake_msg(node2_priv_static_k, text_ack_msg_c)
    if dec_auth_msg is not None and dec_ack_msg is not None:
        print("TestDecrypt(): [PASSED]")
    else: print("TestDecrypt(): [FAILED]")