from pydevp2p.rlp.types import ip_address, hex_value, date_value
from pydevp2p.rlp.utils import bytes_to_typestr, unwrap_rlp
from pydevp2p.utils import bytes_to_hex, bytes_to_int, dict_to_depth_str_list, framectx
from rlp.sedes import big_endian_int, binary
from pydevp2p.rlp.extention import RLPMessage
from rlp.codec import decode
from rlp.sedes import CountableList


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


class FromInfo(RLPMessage):
    fields = (("IP_Address", ip_address), ("UDP_Port",
              big_endian_int), ("TCP_Port", big_endian_int))


class ToInfo(RLPMessage):
    fields = (('IP_Address', ip_address),
              ('UDP_Port', big_endian_int), ("None", binary))


class Packet(object):
    """
    Packet is implemented by all message types.
    """
    class Ping(RLPMessage):
        fields = (("Version", big_endian_int), ("Sender_Info", FromInfo), ("Recipient_Info",
                  ToInfo), ("Exipration", date_value), ("ENR_Sequence_Num", big_endian_int))

    class Pong(RLPMessage):
        fields = (("Recipient_Info", ToInfo), ("Ping_Hash", hex_value),
                  ("Expiration", date_value), ("ENR_Sequence_Num", big_endian_int))

    class FindNode(RLPMessage):
        fields = (("Target", hex_value), ("Expiration", date_value))

    class Neighbors(RLPMessage):
        class NeighborNode(RLPMessage):
            fields = (("IP_Address", ip_address), ("UDP_Port", big_endian_int), ("TCP_Port", big_endian_int),
                      ("Node_ID", hex_value))
        fields = (("Nodes", CountableList(NeighborNode)),
                  ("Expiration", date_value))

    class ENRRequest(RLPMessage):
        fields = [("Expiration", date_value)]

    class ENRResponse:
        STRUCTURE = [("Request_Hash", "hex"), [
            ("Signature", "hex"), ("Sequence_#", "int")]]
        RECORD_ENTRY = {
            "eth": [[("Fork Hash", "hex"), ("Fork Next", "hex")]],
            "les": [("VFlux Version", "int")],
            "id": "str",
            "ip": "ip",
        }

        def __init__(self, raw: bytes) -> None:
            body = decode(raw, strict=False)
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

        def get_fields(self) -> list[str]:
            return dict_to_depth_str_list(self.__dict__)

    # Code-Type Mappings
    code_types: list[RLPMessage] = [None, Ping, Pong,
                                    FindNode, Neighbors, ENRRequest, ENRResponse]

    def __init__(self, code: int, raw: bytes) -> None:
        msg_type = self.code_types[code]
        self.Name = msg_type.__name__.upper() if msg_type is not None else "UNKNOWN"
        self.Kind = code
        self.fields: list[str] = []

        dec = None
        if msg_type is None:
            print(f"{framectx()} DiscV4 Packet Unimplemented/Unknown Msg Code {code}")
            return
        elif code == 6:
            enr_response: Packet.ENRResponse = msg_type(raw)
            self.fields = enr_response.get_fields()
        else:
            try:
                dec = decode(raw, sedes=msg_type, strict=False)
                self.fields = dec.as_str_list()
            except BaseException as e:
                print(f"{framectx()} DiscV4 Packet Err Unable to Decode Msg : {e}")
                return
            if not isinstance(dec, RLPMessage):
                print(f"{framectx()} DiscV4 Packet Err Invalid Msg Type : {dec}")
                return

    def __str__(self) -> str:
        ret = f"Discv4 Packet:"
        ret += f"\n  Name: {self.Name}"
        ret += f"\n  Kind: {self.Kind}"
        for field in self.fields:
            ret += f"\n  {field}"
        return ret

    def getValues(self) -> list[int | str]:
        ret: list[int | str] = [
            len(self.__dict__.items()) + len(self.fields) - 1]
        ret.append(f"Name: {self.Name}")
        ret.append(f"Kind: {self.Kind}")
        for field in self.fields:
            ret.append(field)
        return ret

    def getTypeString(self) -> str:
        return f"[DiscoveryV4 {self.Name}] Version=4 Kind={self.Kind}"


def decodeMessageByType(msg_id: int, body: bytes) -> Packet | None:
    try:
        return Packet(msg_id, body)
    except BaseException as e:
        print(f"{framectx()} decodeMessageByType(msg_id, body) Err ({msg_id}) : {e}")
        return None
