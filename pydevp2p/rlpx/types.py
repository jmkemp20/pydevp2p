from pydevp2p.rlpx.utils import deserialize_rlp
from pydevp2p.utils import bytes_to_hex

class RLPxCapabilityMsg:
    """
    _summary
    """
    def __init__(self, type: str, code: int, msg: list[bytes], code_types: list, msg_types: dict) -> None:
        self.cap = type
        self.type = f"[{type.upper()} {self.code_types[code]}] Type={self.code_types[code]} Code={code}"
        self.code = code
        self.msg = msg
        self.code_types = code_types
        self.msg_types = msg_types
        
        self.d_msg = deserialize_rlp(msg, self.msg_types.get(self.code_types[code]))
        # print()
        # print(f"{type.upper()}: {code}, {self.code_types[code]}: {self.d_msg}")
        return
            
    def __str__(self) -> str:
        ret = ""
        vals = self.getValues()
        for i in range(1, len(vals)):
            ret += f"  {vals[i]}\n"
        return f"RLPxCapabilityMsg:\n{ret}"
    
    def getValues(self):
        ret = [len(self.d_msg) + 1]
        ret.append(f"Type: {self.cap.upper()} {self.code}, {self.code_types[self.code]}")
        ret.extend(self.d_msg)
        return ret
    

class RLPxP2PMsg:
    """First packet sent over the connection, and sent once by both sides. No other 
    messages may be sent until a Hello is received. Implementations must ignore any 
    additional list elements in Hello because they may be used by a future version."""
    msg_types = ["Hello", "Disconnect", "Ping", "Pong"]
    
    def __init__(self, code: int, msg: list[bytes]) -> None:
        self.code = code
        self.type = f"[P2P {self.msg_types[code]}] Type={self.msg_types[code]} Code={code}"
        if code == 0:
            protocolVersion, clientId, capabilities, listenPort, nodeKey, *self.other = msg
            self.protocolVersion = protocolVersion[0]
            self.clientId = clientId.decode("utf-8")
            self.listenPort = listenPort.decode("utf-8") if len(listenPort) > 0 else "N/A"
            self.nodeKey = nodeKey
            self.capabilities = []
            for capability in capabilities:
                name = capability[0].decode("utf-8")
                version = capability[1][0]
                self.capabilities.append(f"{name}: {version}")
            self.capabilities = ", ".join(self.capabilities)
        elif code == 1:
            self.reason = msg[0]
            
    def __str__(self) -> str:
        ret = ""
        vals = self.getValues()
        for i in range(1, len(vals)):
            ret += f"  {vals[i]}\n"
        return f"RLPxP2PMsg:\n{ret}"
            
    def getValues(self) -> list[str]:
        ret = [
            1,
            f"Type: P2P {self.code}, {self.msg_types[self.code]}",
        ]
        if self.code == 0:
            ret.append(f"ProtocolVersion: {self.protocolVersion}")
            ret.append(f"ClientId: {self.clientId}")
            ret.append(f"Capabilities: {self.capabilities}")
            ret.append(f"ListenPort: {self.listenPort}")
            ret.append(f"NodeKey: {bytes_to_hex(self.nodeKey)}")
            ret[0] = 6
        elif self.code == 1:
            ret.append(f"Reason: {self.reason}")
            ret[0] = 2
        return ret
            
        
    @staticmethod
    def validate(code: int, msg: list[bytes]) -> bool:
        if code < 0:
            print("RLPxCapabilityMsgv5 validate(code, msg) Err Invalid Msg Code")
            return False
        if code > 3:
            print("RLPxCapabilityMsgv5 validate(code, msg) Err Unsupported Msg Code")
            return False
        if code == 0 and len(msg) >= 5:
            # Check valid Hello Msg
            return True
        elif code == 1 and len(msg) == 1:
            # Check valid Disconnect Msg
            return True
        elif code == 1 and len(msg) == 1:
            # Check valid Disconnect Msg
            return True
        elif len(msg) == 0:
            # Check valid Ping/Pong Msg
            return True
        print("RLPxCapabilityMsgv5 validate(code, msg) Err Invalid Msg")
        return False


#################################################################
# NOTE The following are Handshake AUTH and AUTH ACK Types only #
#################################################################

SSK_LEN = 16 # max shared key length (pubkey) / 2
SIG_LEN = 65 # elliptic S256 secp256k1
PUB_LEN = 64 # 512 bit pubkey in uncompressed format
SHA_LEN = 32 # Hash Length (for nonce, etc)

class AuthMsgV4:
    """RLPx v4 handshake auth (defined in EIP-8)."""
    def __init__(self, msg: list[bytes]) -> None:
        # Should call validate before creating this object
        self.Signature, self.InitatorPubkey, self.Nonce, self.Version, *extra = msg
        self.RandomPrivKey = extra[0] if len(extra) > 0 else None
            
    def __str__(self) -> str:
        signature = f"Signature:\t\t{bytes_to_hex(self.Signature)}"
        initPubK = f"InitatorPubkey:\t{bytes_to_hex(self.InitatorPubkey)}"
        nonce = f"Nonce:\t\t{bytes_to_hex(self.Nonce)}"
        version = f"Version:\t\t{bytes_to_hex(self.Version)}"
        randPrivk = f"RandomPrivKey:\t{bytes_to_hex(self.RandomPrivKey)}"
        return f"AuthMsgV4:\n  {signature}\n  {initPubK}\n  {nonce}\n  {version}\n  {randPrivk}"
    
    def getValues(self) -> list[str]:
        return [
            5,
            f"Signature: {bytes_to_hex(self.Signature)}",
            f"InitatorPubkey: {bytes_to_hex(self.InitatorPubkey)}",
            f"Nonce: {bytes_to_hex(self.Nonce)}",
            f"Version: {bytes_to_hex(self.Version)}",
            f"RandomPrivKey: {bytes_to_hex(self.RandomPrivKey)}"
        ]
        
        # return {
        #     "Signature": bytes_to_hex(self.Signature), 
        #     "InitatorPubkey": bytes_to_hex(self.InitatorPubkey),
        #     "Nonce": bytes_to_hex(self.Nonce),
        #     "Version": bytes_to_hex(self.Version),
        #     "RandomPrivKey": bytes_to_hex(self.RandomPrivKey)
        # }
    
    @staticmethod
    def validate(msg: list[bytes]) -> bool:
        if len(msg) < 4:
            return False
        if len(msg[0]) != SIG_LEN or len(msg[1]) != PUB_LEN or len(msg[2]) != SHA_LEN or len(msg[3]) != 1:
            return False
        return True
    
    
class AuthRespV4:
    """RLPx v4 handshake response (defined in EIP-8)."""
    def __init__(self, msg: list[bytes]) -> None:
        # Should call validate before creating this object
        self.RandomPubkey, self.Nonce, self.Version, *extra = msg
        self.RandomPrivKey = extra[0] if len(extra) > 0 else None
            
    def __str__(self) -> str:
        randPubKey = f"RandomPubkey:\t\t{bytes_to_hex(self.RandomPubkey)}"
        nonce = f"Nonce:\t\t{bytes_to_hex(self.Nonce)}"
        version = f"Version:\t\t{bytes_to_hex(self.Version)}"
        randPrivk = f"RandomPrivKey:\t{bytes_to_hex(self.RandomPrivKey)}"
        return f"AuthRespV4:\n  {randPubKey}\n  {nonce}\n  {version}\n  {randPrivk}"
        
    def getValues(self) -> dict[str, str]:
        return [
            4,
            f"RandomPubkey: {bytes_to_hex(self.RandomPubkey)}",
            f"Nonce: {bytes_to_hex(self.Nonce)}",
            f"Version: {bytes_to_hex(self.Version)}",
            f"RandomPrivKey: {bytes_to_hex(self.RandomPrivKey)}"
        ]
        # return {
        #     "RandomPubkey": bytes_to_hex(self.RandomPubkey), 
        #     "Nonce": bytes_to_hex(self.Nonce),
        #     "Version": bytes_to_hex(self.Version),
        #     "RandomPrivKey": bytes_to_hex(self.RandomPrivKey)
        # }
    
    @staticmethod
    def validate(msg: list[bytes]) -> bool:
        if len(msg) < 3:
            return False
        if len(msg[0]) != PUB_LEN or len(msg[1]) != SHA_LEN or len(msg[2]) != 1:
            return False
        return True