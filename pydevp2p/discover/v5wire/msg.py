
# geth/p2p/discover/v5wire/msg.go
from rlp.codec import decode

from pydevp2p.discover.datatypes import Enode, Record
from pydevp2p.rlp.utils import cleanse_rlp
from pydevp2p.utils import bytes_to_hex, bytes_to_int, framectx


class Packet:
    """
    Packet is implemented by all message types.
    """

    def __init__(self, name: str, kind: int, requestID: bytes) -> None:
        self.name = name
        self.kind = kind  # byte (uint8 - 0 - 255)
        self.requestID = requestID
        return

    def __str__(self) -> str:
        ret = f"Discv5 Packet:"
        for attr, val in self.__dict__.items():
            cleansedVal = val
            if isinstance(val, bytes):
                cleansedVal = bytes_to_hex(val) if len(
                    val) > 8 else bytes_to_int(val)
            if isinstance(val, list):
                cleansedVal = ", ".join(cleanse_rlp(val))
            ret += f"\n  {attr.capitalize()}: {cleansedVal}"
        return ret

    def getValues(self) -> list[str]:
        ret = [len(self.__dict__.items())]
        for attr, val in self.__dict__.items():
            cleansedVal = val
            if isinstance(val, bytes):
                cleansedVal = bytes_to_hex(val) if len(
                    val) > 8 else bytes_to_int(val)
            if isinstance(val, list):
                cleansedVal = ", ".join(cleanse_rlp(val))
            ret.append(f"{attr.capitalize()}: {cleansedVal}")
        return ret

    def getTypeString(self, headerType: str) -> str:
        return f"[DiscoveryV5 {headerType} {self.name}] Version=5 Kind={self.kind} RequestID={self.requestID}"


class Unknown(Packet):
    # Unknown represents any packet that can't be decrypted.
    def __init__(self, nonce: bytes) -> None:
        super().__init__("UNKNOWN/v5", 255, None)
        self.nonce = nonce


class Whoareyou(Packet):
    # Whoareyou contains the handshake challenge.
    def __init__(self, challengeData: bytes, nonce: bytes, idNonce: bytes, recordSeq: bytes) -> None:
        super().__init__("WHOAREYOU/v5", 254, None)
        self.challengeData = challengeData  # Encoded challenge
        self.nonce = nonce  # Nonce of request packet (12 bytes)
        self.idNonce = idNonce  # Identity proof data (16 bytes)
        # ENR sequence number of recipient (uint64 - 8 bytes)
        self.recordSeq = recordSeq
        # The following is the locally known ifo of the recipient
        # .. These must be set by the caller of Encode
        self.node: Enode = None


class Ping(Packet):
    # Ping is sent during liveness checks.
    def __init__(self, reqID: bytes, enrSeq: bytes) -> None:
        super().__init__("PING/v5", 1, reqID)
        self.enrSeq = enrSeq


class Pong(Packet):
    # Pong is the reply to Ping.
    def __init__(self, reqID: bytes, enrSeq: bytes, toIP: bytes, toPort: bytes) -> None:
        super().__init__("PONG/v5", 2, reqID)
        self.enrSeq = enrSeq
        # These fields should mirror the UDP envelope address of the ping
        # .. packet, which provides a way to discover the external address (after NAT).
        self.toIP = ".".join(f'{c}' for c in toIP)
        self.toPort = toPort


class FindNode(Packet):
    # Findnode is a query for nodes in the given bucket.
    def __init__(self, reqID: bytes, distances: list[int]) -> None:
        super().__init__("FINDNODE/v5", 3, reqID)
        self.distances = distances


class Nodes(Packet):
    # Nodes is the reply to Findnode and Topicquery.
    def __init__(self, reqID: bytes, total: int, nodes: list[Record]) -> None:
        super().__init__("NODES/v5", 4, reqID)
        self.total = total
        self.nodes = nodes


class TalkRequest(Packet):
    # TalkRequest is an application-level request.
    def __init__(self, reqID: bytes, protocol: str, message: bytes) -> None:
        super().__init__("TALKREQ/v5", 5, reqID)
        self.protocol = protocol
        self.message = message


class TalkResponse(Packet):
    # TalkResponse is the reply to TalkRequest.
    def __init__(self, reqID: bytes, message: bytes) -> None:
        super().__init__("TALKRESP/v5", 6, reqID)
        self.message = message


class RequestTicket(Packet):
    # RequestTicket requests a ticket for a topic queue.
    def __init__(self, reqID: bytes, topic: bytes) -> None:
        super().__init__("REQTICKET/v5", 7, reqID)
        self.topic = topic


class Ticket(Packet):
    # Ticket is the response to RequestTicket.
    def __init__(self,  reqID: bytes, ticket: bytes) -> None:
        super().__init__("TICKET/v5", 8, reqID)
        self.ticket = ticket


class RegTopic(Packet):
    # Regtopic registers the sender in a topic queue using a ticket.
    def __init__(self, reqID: bytes, ticket: bytes, enr: Record) -> None:
        super().__init__("REGTOPIC/v5", 9, reqID)
        self.ticket = ticket
        self.ENR = enr


class RegConfirmation(Packet):
    # Regconfirmation is the reply to Regtopic.
    def __init__(self, reqID: bytes, registered: bool) -> None:
        super().__init__("REGCONFIRMATION/v5", 10, reqID)
        self.registered = registered


class TopicQuery(Packet):
    # TopicQuery asks for nodes with the given topic.
    def __init__(self, reqID: bytes, topic: bytes) -> None:
        super().__init__("TOPICQUERY/v5", 11, reqID)
        self.topic = topic


ptypes = [Ping, Pong, FindNode, Nodes, TalkRequest, TalkResponse,
          RequestTicket, Ticket, RegTopic, RegConfirmation, TopicQuery]


def decodeMessageByType(ptype: int, body: bytes) -> Packet | None:
    if len(ptypes) < ptype < 1:
        print(
            f"{framectx()} decodeMessageByType(ptype, body) Err Invalid ptype: {ptype}")
        return None

    dec: list[bytes] = None
    try:
        dec = decode(body, strict=False)
    except BaseException as e:
        print(f"{framectx()} decodeMessageByType(ptype, body) Err {e}")
        return None
    if dec is None:
        print(
            f"{framectx()} decodeMessageByType(ptype, body) Err Unable to RLP Decode Message")
        return None

    if len(dec) == 2:
        return ptypes[ptype - 1](dec[0], dec[1])
    elif len(dec) == 3:
        return ptypes[ptype - 1](dec[0], dec[1], dec[2])
    elif len(dec) == 4:
        return ptypes[ptype - 1](dec[0], dec[1], dec[2], dec[3])

    print(f"{framectx()} decodeMessageByType(ptype, body) Err Unable to Parse Message")
    return None
