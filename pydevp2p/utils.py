from inspect import currentframe, getframeinfo
import os
# Contains general utility functions


def int_to_bytes(i: int, *, signed: bool = False) -> bytes:
    length = ((i + ((i * signed) < 0)).bit_length() + 7 + signed) // 8
    return i.to_bytes(length, byteorder='big', signed=signed)


def hex_to_bytes(hex: str, *, signed: bool = False) -> bytes:
    return bytes.fromhex(hex)


def bytes_to_int(b: bytes, *, signed: bool = False) -> int:
    return int.from_bytes(b, byteorder='big', signed=signed)


def bytes_to_hex(b: bytes | None, *, signed: bool = False) -> str:
    if not isinstance(b, bytes):
        return "None"
    return bytes.hex(b)


def read_uint24(b: bytes) -> int:
    return b[2] | b[1] << 8 | b[0] << 16


def ceil16(x: int) -> int:
    return x if x % 16 == 0 else x + 16 - (x % 16)


def framectx():
    cf = currentframe()
    fn = getframeinfo(cf.f_back).filename.split(os.sep)
    idx = -1
    for i in range(len(fn)):
        if fn[i] == "pydevp2p":
            idx = i
    fn = os.sep.join(fn[idx:])
    return f"[{fn} {cf.f_back.f_lineno}]"


def flatten_dict(d: dict) -> dict:
    ret = {}

    def flatten(d2: dict):
        for k, v in d2.items():
            check_val(k, v)

    def check_val(k: str, v):
        if not isinstance(v, dict):
            ret[k] = v
        else:
            flatten(v)
    for k, v in d.items():
        check_val(k, v)
    return ret


def dict_to_str_list(d: dict) -> list:
    """Will place all top level fields in dict in its own element in the list

    i.e. { a: ..., b: ..., c: ...} => ['a: ...', 'b: ...', 'c: ...']

    Args:
        d (dict): Preferebly a flat dict

    Returns:
        list: Flat list of strings ["key: value"] pairs
    """
    ret = []
    for k, v in d.items():
        key = k.replace("_", " ")
        value = v if not isinstance(
            v, dict) else ", ".join(dict_to_str_list(v))
        ret.append(f"{key}: {value}")
    return ret


def dict_to_flat_str(d: dict) -> str:
    ret = ""
    for k, v in d.items():
        key = k.replace("_", " ")
        value = v if not isinstance(v, dict) else ",".join(dict_to_str_list(v))
        if len(ret) > 0:
            ret += ", "
        ret += f"{key}: {value}"
    return ret


def dict_to_depth_str_list(d: dict) -> list:
    """_summary_

    Args:
        d (dict): _description_

    Returns:
        list: Flat list of strings ["key: value"] pairs but with "\t" to symbolize depth
    """
    ret = []

    def parse_dict(dd: dict, depth=1):
        tabs = '   ' * depth
        cutoff = 128
        for k, v in dd.items():
            key = k.replace("_", " ")
            if isinstance(v, dict):
                val = " N/A" if len(v) == 0 else ""
                ret.append(f"{tabs}{key}:{val}")
                parse_dict(v, depth=depth + 1)
            else:
                is_str = False
                cleansed = v
                if isinstance(v, str) and len(v) > cutoff:
                    is_str = True
                    cleansed = v[:cutoff]
                ret.append(f"{tabs}{key}: {cleansed}")
                if is_str:
                    new_str = v[len(cleansed):]
                    remaining_len = len(new_str)
                    while remaining_len > 0:
                        key_spacing = " " * (len(key) + 2)
                        cleansed = new_str[:cutoff]
                        new_str = new_str[len(cleansed):]
                        remaining_len = len(new_str)
                        ret.append(f"{tabs}{key_spacing}{cleansed}")

    for k, v in d.items():
        key = k.replace("_", " ")
        if isinstance(v, dict):
            val = " N/A" if len(v) == 0 else ""
            ret.append(f"{key}:{val}")
            parse_dict(v)
        else:
            ret.append(f"{key}: {v}")
    return ret
