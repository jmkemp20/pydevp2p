import snappy
from Crypto.Hash import keccak
from Crypto.Util import Counter
from rlp.codec import decode
from rlp.sedes import big_endian_int

from pydevp2p.crypto.params import ECIES_AES128_SHA256
from pydevp2p.rlp.extention import RLPMessage
from pydevp2p.rlpx.capabilities import RLPxCapabilityMsg, get_rlpx_capability_msg
from pydevp2p.rlpx.handshake import Secrets
from pydevp2p.rlpx.types import RLPxP2PMsg
from pydevp2p.utils import bytes_to_hex, bytes_to_int, ceil16, dict_to_flat_str, framectx, read_uint24


class FrameHeader:
    """_summary_

    Returns:
        _type_: _description_
    """
    headerSize = 32

    class Capabilities(RLPMessage):
        fields = (("Capability_ID", big_endian_int),
                  ("Context_ID", big_endian_int))

    def __init__(self, header: bytes, raw_data: bytes) -> None:
        self.header = bytes_to_hex(header)
        self.headerCiphertext = raw_data[:16]
        self.mac = bytes_to_hex(raw_data[16:])
        # Get the frame size from the first 3 bytes
        # ..frameSize = struct.unpack(b'>I', b'\x00' + header[:3])[0]
        self.frameSize = read_uint24(header)
        # Round up frame size to 16 byte boundary for padding
        self.readSize = ceil16(self.frameSize)
        headerDec = None
        try:
            headerDec = decode(
                header[3:], sedes=self.Capabilities, strict=False)
        except BaseException as e:
            print(f"{framectx()} FrameHeader Err Unable to Decode Header : {e}")
        if headerDec is not None:
            self.headerData = dict_to_flat_str(headerDec.as_flat_dict())
        else:
            self.headerData = header[3:]
        return

    def __str__(self) -> str:
        ret = f"RLPx Header:"
        for attr, val in self.__dict__.items():
            cleansed = val
            if isinstance(val, bytes):
                cleansed = bytes_to_hex(val) if len(
                    val) > 6 else bytes_to_int(val)
            ret += f"\n  {attr.capitalize()}: {cleansed}"
        return ret


class HashMAC:
    """HashMAC holds the state of the RLPx v4 MAC contraption"""

    def __init__(self) -> None:
        self.cipher = None
        self.hash = keccak.new(digest_bits=256)
        self.aesBuffer = [b'\x00'] * 16
        self.hashBuffer = [b'\x00'] * 32
        self.seedBuffer = [b'\x00'] * 32

    def computeHeader(self, header: bytes) -> bytes:
        return

    def computeFrame(self, framedata: bytes) -> bytes:
        return

    def computer(self, sum1: bytes, seed: bytes) -> bytes:
        return


class SessionState:
    """Contains the session keys"""

    def __init__(self, secrets: Secrets) -> None:
        self.params = ECIES_AES128_SHA256()
        self.aes_key = secrets.aes
        self.ctr = Counter
        self.cipher = self.params.Cipher
        # all you need to call instead of .XORKeyStream is just .decrypt(ct) or .encrypt(m)
        # 0 IV because the key for encryption is ephemeral
        enc_ctr = Counter.new(self.params.BlockSize * 8, initial_value=0)
        self.enc = self.cipher.new(
            secrets.aes, self.params.Cipher.MODE_CTR, counter=enc_ctr)
        # 0 IV because the key for encryption is ephemeral
        dec_ctr = Counter.new(self.params.BlockSize * 8, initial_value=0)
        self.dec = self.cipher.new(
            secrets.aes, self.params.Cipher.MODE_CTR, counter=dec_ctr)
        self.egressMac = HashMAC()
        self.ingressMac = HashMAC()
        self.handshakeCompleted = False

    def __str__(self) -> str:
        ret = f"RLPx SessionState:"
        for attr, val in self.__dict__.items():
            cleansed = val
            if isinstance(val, bytes):
                cleansed = bytes_to_hex(val) if len(
                    val) > 6 else bytes_to_int(val)
            ret += f"\n  {attr.capitalize()}: {cleansed}"
        return ret

    def _decryptHeader(self, headerData: bytes) -> bytes | None:
        if len(headerData) != 32:
            print(
                f"{framectx()} SessionState _decryptHeader(headerData) Err Invalid headerData Len")
            return None

        header_ciphertext = headerData[:16]
        header_mac = headerData[16:]

        if len(header_mac) != 16:
            print(
                f"{framectx()} SessionState _decryptHeader(headerData) Err Invalid MAC Len")
            return None

        # TODO verify header_mac
        return self.dec.decrypt(header_ciphertext)

    def _decryptBody(self, bodyData: bytes, readSize: int) -> bytes | None:
        if not len(bodyData) >= readSize + 16:
            print(f"{framectx()} SessionState _decryptBody(bodyData, readSize) Err Insufficient Body Len {len(bodyData)}, Expected {len(bodyData)} >= {readSize + 16}")
            return None

        frame_ciphertext = bodyData[:readSize]
        frame_mac = bodyData[readSize: readSize + 16]

        if len(frame_mac) != 16:
            print(
                f"{framectx()} SessionState _decryptBody(bodyData, readSize) Err Invalid MAC Len")
            return None

        # TODO verify frame_mac

        return self.dec.decrypt(frame_ciphertext)

    def readFrame(self, data: bytes) -> tuple[FrameHeader, RLPxP2PMsg | RLPxCapabilityMsg | None] | None:
        """SessionState readFrame reads and decrypts message frames, which are all
        messages that follow the initial handshake. A frame carries a single encrypted
        message belonging to a capability. This function allows for both decrypting
        and verification of frame data.

        https://github.com/ethereum/devp2p/blob/master/rlpx.md

        Hello: frame-data = msg-id || msg-data
        All messages following Hello are compressed using the Snappy algorithm.
        After: frame-data = msg-id || snappyCompress(msg-data)

        Args:
            data (bytes): The encrypted message frame to be decrypted and verified

        Returns:
            bytes | None: The decrypted message frame or None if an error occurred
        """
        headerSize = FrameHeader.headerSize
        # Read the frame header
        header = self._decryptHeader(data[:headerSize])
        # print("header:", header.hex())
        if header is None:
            print(
                f"{framectx()} SessionState readFrame(data) Err Unable to Decrypt Header of size: {headerSize}")
            return None

        try:
            frameHeader = FrameHeader(header, data[:headerSize])
        except BaseException as e:
            print(f"{framectx()} SessionState readFrame(data) Err : {e}")
            return None

        # Decrypt and verify frame-ciphertext and frame-mac
        frame = self._decryptBody(data[headerSize:], frameHeader.readSize)
        # print("frame[:frameSize]:", bytes_to_hex(frame[:frameSize]))
        if frame is None:
            print(
                f"{framectx()} SessionState readFrame(data) Err Unable to Decrypt Frame Body of size: {len(data[headerSize:])}")
            return frameHeader, None

        code = decode(frame[:1], sedes=big_endian_int, strict=False)

        # The first RLPx message after handshake should always be a Hello msg
        if not self.handshakeCompleted:
            dec_frame = decode(frame[1:frameHeader.frameSize], strict=False)
            if dec_frame is None:
                print(
                    f"{framectx()} SessionState readFrame(data) Err Unable to Decode Frame")
                return frameHeader, None

            if not RLPxP2PMsg.validate(code, dec_frame):
                print(
                    f"{framectx()} SessionState readFrame(data) Err Unable to Validate RLPxP2PMsg {code}: {dec_frame}")
                return frameHeader, None
            self.handshakeCompleted = True

            # TODO Msg ids are layed out in blocks based on capability name/version and are calculated by each
            # .. peer from their capability lists in the Hello msg.

            return frameHeader, RLPxP2PMsg(code, dec_frame)

        # Snappy Decompression
        decompress = snappy.decompress(frame[1:frameHeader.frameSize])

        # print(f"code: {code}, Decompressed:", bytes_to_hex(decompress))

        # RLP Decoding of Snappy decompressed data
        dec_decompress = None
        try:
            dec_decompress = decode(decompress, strict=False)
        except BaseException as e:
            print(f"SessionState readFrame(data) decode(m, strict=False): {e}")
            return frameHeader, None
        if dec_decompress is None:
            print(
                f"{framectx()} SessionState readFrame(data) Err Unable to Decode Decompressed Frame Body")
            return frameHeader, None

        # check for code 1,2,3 (DISCONNECT, PING, PONG)
        if code == 1 or code == 2 or code == 3:
            if not RLPxP2PMsg.validate(code, dec_decompress):
                print(
                    f"{framectx()} SessionState readFrame(data) Err Unable to Validate RLPxP2PMsg {code}: {dec_decompress}")
                return frameHeader, None
            return frameHeader, RLPxP2PMsg(code, dec_decompress)

        # TODO This is now where each capability splits off and has their own messaging scheme
        # .. https://github.com/ethereum/devp2p/tree/master/caps
        return frameHeader, get_rlpx_capability_msg(code, decompress)

    def writeFrame(self, code: int, data: bytes) -> bytes | None:
        # Place holder
        return
