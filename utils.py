# Contains general utility functions

def int_to_bytes(i: int, *, signed: bool = False) -> bytes:
    length = ((i + ((i * signed) < 0)).bit_length() + 7 + signed) // 8
    return i.to_bytes(length, byteorder='big', signed=signed)

def hex_to_bytes(hex: str, *, signed: bool = False) -> bytes:
    return int_to_bytes(int(hex, 16), signed=signed)

def bytes_to_int(b: bytes, *, signed: bool = False) -> int:
    return int.from_bytes(b, byteorder='big', signed=signed)

def bytes_to_hex(b: bytes, *, signed: bool = False) -> str:
    return hex(bytes_to_int(b, signed=signed))[2:]