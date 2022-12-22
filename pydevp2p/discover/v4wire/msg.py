from pydevp2p.rlp.types import ip_address, hex_value, date_value
from pydevp2p.rlp.utils import bytes_to_typestr, format_time, unwrap_rlp
from pydevp2p.utils import bytes_to_hex, bytes_to_int, dict_to_str_list, flatten_dict, framectx
from rlp.sedes import big_endian_int, binary
from pydevp2p.rlp.extention import RLPMessage
from rlp.codec import decode


class Header:
    """
    Generic discoveryV4 Header that exists on every discv4 packet
    """
    PACKET_TYPES = ["Unknown", "Ping", "Pong", "FindNode",
                    "Neighbors", "ENRRequest", "ENRResponse"]

    def __init__(self, hash, sig, type) -> None:
        self.hash = bytes_to_hex(hash)
        self.sig = bytes_to_hex(sig)
        self.type = bytes_to_int(type)
        self.name = self.PACKET_TYPES[self.type]

    def __str__(self) -> str:
        ret = f"Discv4 Header:"
        for attr, val in self.__dict__.items():
            ret += f"\n  {attr.capitalize()}: {val}"
        return ret

    def getValues(self) -> list[str]:
        ret = [len(self.__dict__.items())]
        for attr, val in self.__dict__.items():
            ret.append(f"{attr.capitalize()}: {val}")
        return ret


class Packet(object):
    """
    Packet is implemented by all message types.
    """
    class RLP(RLPMessage):
        fields = ()

    def __init__(self, name: str, kind: int) -> None:
        self.Name = name
        self.Kind = kind
        return

    def __str__(self) -> str:
        ret = f"Discv4 Packet:"
        for attr, val in self.__dict__.items():
            field = attr.replace("_", " ")
            ret += f"\n  {field}: {val}"
        return ret

    def getValues(self) -> list[str]:
        ret = [len(self.__dict__.items())]
        for attr, val in self.__dict__.items():
            field = attr.replace("_", " ")
            ret.append(f"{field}: {val}")
        return ret

    def getTypeString(self) -> str:
        return f"[DiscoveryV4 {self.Name}] Version=4 Kind={self.Kind}"


class ToMsg(RLPMessage):
    fields = (('Recipient_IP_Address', ip_address),
              ('Recipient_UDP_Port', big_endian_int), ("None", binary))


class Unknown(Packet):
    # Unknown represents any packet that can't be decrypted.
    def __init__(self) -> None:
        super().__init__("UNKNOWN/v4", 0)


class Ping(Packet):
    # Ping is sent during liveness checks.
    STRUCTURE = [("Version", "int"), [("Sender_IP", "ip"), ("Sender_UDP_Port", "int"), ("Sender_TCP_Port", "int")],
                 [("Recipient_IP", "ip"), ("Recipient_UDP_Port", "int"), ("", "")], ("Expiration", "date"), ("ENR_Sequence_#", "int")]

    def __init__(self, entries: list[str]) -> None:
        super().__init__("PING", 1)


class Pong(Packet):
    # Pong is the reply to Ping.
    class RLP(RLPMessage):
        fields = (('to', ToMsg), ("Ping_Hash", hex_value),
                  ("Expiration", date_value), ("ENR_Sequence", big_endian_int))

    def __init__(self, entries: list[str]) -> None:
        super().__init__("PONG", 2)
        for entry in entries:
            key, value = entry.split(": ")
            setattr(self, key, value)


class FindNode(Packet):
    # Findnode is a query for nodes in the given bucket.
    STRUCTURE = [("Target", "hex"), ("Expiration", "date")]

    def __init__(self, entries: list[str]) -> None:
        super().__init__("FINDNODE", 3)
        for entry in entries:
            key, value = entry.split(": ")
            setattr(self, key, value)


class Neighbors(Packet):
    # Neighbors is the reply to FindNode
    STRUCTURE = [[[("IP", "ip"), ("UDP_Port", "int"), ("TCP_Port", "int"),
                   ("Node_ID", "hex")]], ("Expiration", "date")]

    def __init__(self, body: list[str]) -> None:
        super().__init__("NEIGHBORS", 4)
        neighbors = body[0]
        num_neighbors = len(neighbors)
        for i in range(num_neighbors):
            # ["IP", "UDP_Port", "TCP_Port", "Node_ID"]
            # ["ip", "int", "int", "hex"]
            ip, udp, tcp, id = unwrap_rlp(
                neighbors[i], self.STRUCTURE[0][0], False)
            setattr(self, f"Neighbor {i + 1})", f"{ip}:{udp}/{tcp} {id}")
        self.Expiration = format_time(body[1])


class ENRRequest(Packet):
    # ENRRequest is a query for a nodes ENR record
    STRUCTURE = [("Expiration", "date")]

    def __init__(self, entries: list[str]) -> None:
        super().__init__("ENRRequest", 5)
        for entry in entries:
            key, value = entry.split(": ")
            setattr(self, key, value)


class ENRResponse(Packet):
    # ENRResponse is the reply to ENRRequest
    STRUCTURE = [("Request_Hash", "hex"), [
        ("Signature", "hex"), ("Sequence_#", "int")]]
    RECORD_ENTRY = {
        "eth": [[("Fork Hash", "hex"), ("Fork Next", "hex")]],
        "les": [("VFlux Version", "int")],
        "id": "str",
        "ip": "ip",
    }

    def __init__(self, body: list[str]) -> None:
        super().__init__("ENRResponse", 6)
        entries = unwrap_rlp(body, self.STRUCTURE)
        for entry in entries:
            key, value = entry.split(": ")
            setattr(self, key, value)
        key_vals = body[1][2:]
        for i in range(0, len(key_vals), 2):
            key, value = key_vals[i], key_vals[i + 1]
            key = key.decode("utf-8")
            key_type = self.RECORD_ENTRY.get(key)
            if (key_type):
                if isinstance(key_type, list):
                    dec = ", ".join(unwrap_rlp(value, key_type, True))
                else:
                    dec = bytes_to_typestr(value, key_type)
                setattr(self, key, dec)
            else:
                setattr(self, key, bytes_to_typestr(value, None))


ptypes: list[Packet] = [Unknown, Ping, Pong,
                        FindNode, Neighbors, ENRRequest, ENRResponse]


def decodeMessageByType(ptype: int, body: bytes) -> Packet | None:
    Message = ptypes[ptype]
    # Grab the RLPMessage Subclass to deserialize into field types during decoding
    msg_structure = Message.RLP

    # Use the msg_structure rlp sedes to decode the RLP encoded data
    try:
        decoded_data = decode(body, sedes=msg_structure, strict=False)
    except Exception as e:
        print(f"{framectx()} decodeMessageByType(ptype, body) Err {e}")
        return None
    if decoded_data is None:
        print(
            f"{framectx()} decodeMessageByType(ptype, body) Err Decoded Data is Invalid")
        return None

    # TODO FINISH
    flattend = decoded_data.as_flat_dict()
    print(dict_to_str_list(flattend))
