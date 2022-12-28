import json
# This file is a bridge to handle payload data incoming from a LUA dissector
from pydevp2p.discover.v4wire.decode import decodeDiscv4
from pydevp2p.discover.v4wire.msg import Header as Discv4Header, Packet as Discv4Packet
from pydevp2p.discover.v5wire.encoding import Header as Discv5Header
from pydevp2p.discover.v5wire.msg import Packet as Discv5Packet
from pydevp2p.rlpx.node import Node
from pydevp2p.rlpx.rlpx import FrameHeader
from pydevp2p.rlpx.types import AuthMsgV4, AuthRespV4, RLPxP2PMsg, RLPxCapabilityMsg
from pydevp2p.utils import bytes_to_int, hex_to_bytes

write_to_file = False

boot_priv_static_k = "3028271501873c4ecf501a2d3945dcb64ea3f27d6f163af45eb23ced9e92d85b"
node1_priv_static_k = "4622d11b274848c32caf35dded1ed8e04316b1cde6579542f0510d86eb921298"
node2_priv_static_k = "816efc6b019e8863c382fe94cefe8e408d53697815590f03ce0a5cbfdd5f23f2"
node3_priv_static_k = "3fadc6b2fbd8c7cf1b2292b06ebfea903813b18b287dc29970a8a3aa253d757f"
self_geth_static_k = "a633a66872c6343407cfa4b4d2095850fceb53d85db5247f0f8c27c5252dede6"

all_nodes: dict[str, Node] = {
    "10.1.0.10": Node("10.1.0.10", hex_to_bytes(boot_priv_static_k)),
    "10.1.1.10": Node("10.1.1.10", hex_to_bytes(node1_priv_static_k)),
    "10.1.2.20": Node("10.1.2.20", hex_to_bytes(node2_priv_static_k)),
    "10.1.3.30": Node("10.1.3.30", hex_to_bytes(node3_priv_static_k)),
    "172.23.69.251": Node("10.1.3.30", hex_to_bytes(self_geth_static_k))
}

cache = {

}

recv = []


def handleRLPxHandshakeMsg(srcip: str, dstip: str, payload: str, visited: bool = False, number: int = -1) -> AuthMsgV4 | AuthRespV4 | None:
    src_node = all_nodes.get(srcip)
    dst_node = all_nodes.get(dstip)
    if src_node is None or dst_node is None:
        return None

    if write_to_file and not visited:
        recv.append({"src": srcip, "dst": dstip,
                    "payload": payload, "type": "rlpx-handshake", "visited": visited, "number": number})
        with open('/home/jkemp/cs700/pydevp2p/out.json', 'w') as f:
            json.dump(recv, f)
    key = number if number >= 0 else srcip + dstip + payload
    ret = cache.get(key)
    if not ret:
        try:
            dec = dst_node.readHandshakeMsg(hex_to_bytes(payload), src_node)
        except BaseException as e:
            print(
                f"[BRIDGE] ({number}) handleRLPxHandshakeMsg({srcip} → {dstip}) : {e}")
            return None
        if dec is None:
            print(
                f"[BRIDGE] ({number}) handleRLPxHandshakeMsg({srcip} → {dstip}) : Err Unable to Read Msg")
            return None
        ret = dec.getValues()
        cache[key] = ret

    return ret


def handleRLPxMsg(srcip: str, dstip: str, payload: str, visited: bool = False, number: int = -1) -> tuple[FrameHeader, RLPxP2PMsg | RLPxCapabilityMsg | None, str | None] | None:
    src_node = all_nodes.get(srcip)
    dst_node = all_nodes.get(dstip)
    if src_node is None or dst_node is None:
        return None

    if write_to_file and not visited:
        recv.append({"src": srcip, "dst": dstip,
                    "payload": payload, "type": "rlpx-msg", "visited": visited, "number": number})
        with open('/home/jkemp/cs700/pydevp2p/out.json', 'w') as f:
            json.dump(recv, f)

    key = number if number >= 0 else srcip + dstip + payload
    ret = cache.get(key)
    if not ret:
        try:
            decHeader, decBody = dst_node.readRLPxMsg(
                hex_to_bytes(payload), src_node)
        except BaseException as e:
            print(
                f"[BRIDGE] ({number}) handleRLPxMsg({srcip} → {dstip}) : {e}")
            return None
        if decHeader is None:
            print(
                f"[BRIDGE] ({number}) handleRLPxMsg({srcip} → {dstip}) Err Frame Header None")
            return None
        elif decBody is None:
            print(
                f"[BRIDGE] ({number}) handleRLPxMsg({srcip} → {dstip}) Err Frame Body None")
            return decHeader, None, None
        ret = (decHeader, decBody.getValues(), decBody.type)
        cache[key] = ret

    frameHeader, frameBody, frameType = ret

    return frameHeader, frameBody, frameType


def handleDiscv5Msg(srcip: str, dstip: str, payload: str, visited: bool = False, number: int = -1) -> tuple[Discv5Header, Discv5Packet | None] | None:
    src_node = all_nodes.get(srcip)
    dst_node = all_nodes.get(dstip)
    if src_node is None or dst_node is None:
        return None

    flag_types = ["MESSAGE", "WHOAREYOU", "HANDSHAKE"]

    if write_to_file and not visited:
        recv.append({"src": srcip, "dst": dstip,
                    "payload": payload, "type": "discv5", "visited": visited, "number": number})
        with open('/home/jkemp/cs700/pydevp2p/out.json', 'w') as f:
            json.dump(recv, f)

    key = number if number >= 0 else srcip + dstip + payload
    ret = cache.get(key)
    if not ret:
        try:
            dec_msg = dst_node.readDiscv5Msg(hex_to_bytes(payload), src_node)
            if dec_msg is None:
                return None
            decHeader, decPacket = dec_msg
        except BaseException as e:
            print(
                f"[BRIDGE] ({number}) handleDiscv5Msg({srcip} → {dstip}) : {e}")
            return None
        if decHeader is None:
            print(
                f"[BRIDGE] ({number}) handleDiscv5Msg({srcip} → {dstip}) Err Discv5 Header is None")
            return None
        elif decPacket is None:
            print(
                f"[BRIDGE] ({number}) handleDiscv5Msg({srcip} → {dstip}) Err Discv5 Packet is None")
            return decHeader, None, None
        type = decPacket.getTypeString(
            flag_types[bytes_to_int(decHeader.flag)])
        ret = (decHeader.getValues(), decHeader.getSize(),
               decPacket.getValues(), type)
        cache[key] = ret

    discv5Header, headerSize, discv5Packet, packetType = ret

    return discv5Header, headerSize, discv5Packet, packetType


def handleDiscv4Msg(srcip: str, dstip: str, payload: str, visited: bool = False, number: int = 0) -> tuple[Discv4Header, Discv4Packet | None] | None:
    src_node = all_nodes.get(srcip)
    dst_node = all_nodes.get(dstip)

    if write_to_file and not visited:
        recv.append({"src": srcip, "dst": dstip,
                    "payload": payload, "type": "discv4", "visited": visited, "number": number})
        with open('/home/jkemp/cs700/pydevp2p/out.json', 'w') as f:
            json.dump(recv, f)

    if src_node is None or dst_node is None:
        try:
            dec_msg = decodeDiscv4(hex_to_bytes(payload))
            if dec_msg is None:
                return None
            decHeader, decPacket = dec_msg
        except BaseException as e:
            print(
                f"[BRIDGE] ({number}) handleDiscv4Msg({srcip} → {dstip}) : {e}")
            return None
        if decHeader is None:
            print(
                f"[BRIDGE] ({number}) handleDiscv4Msg({srcip} → {dstip}) Err Discv4 Header is None")
            return None
        elif decPacket is None:
            print(
                f"[BRIDGE] ({number}) handleDiscv4Msg({srcip} → {dstip}) Err Discv4 Packet is None")
            return decHeader.getValues(), None, None
        type = decPacket.getTypeString()
        return decHeader.getValues(), decPacket.getValues(), type
    else:
        try:
            dec_msg = dst_node.readDiscv4Msg(hex_to_bytes(payload), src_node)
            if dec_msg is None:
                return None
            decHeader, decPacket = dec_msg
        except BaseException as e:
            print(
                f"[BRIDGE] ({number}) handleDiscv4Msg({srcip} → {dstip}) : {e}")
            return None
        if decHeader is None:
            print(
                f"[BRIDGE] ({number}) handleDiscv4Msg({srcip} → {dstip}) Err Discv4 Header is None")
            return None
        elif decPacket is None:
            print(
                f"[BRIDGE] ({number}) handleDiscv4Msg({srcip} → {dstip}) Err Discv4 Packet is None")
            return decHeader.getValues(), None, None
        type = decPacket.getTypeString()
        ret = (decHeader.getValues(), decPacket.getValues(), type)

    discv4Header, discv4Packet, packetType = ret

    return discv4Header, discv4Packet, packetType
