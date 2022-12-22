import time
from pydevp2p.utils import bytes_to_hex, bytes_to_int


def format_time(timestamp: int) -> str:
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bytes_to_int(timestamp)))

def bytes_to_typestr(value: bytes, type: str | list = None, fieldname = True) -> str:
    ret = ""
    if len(value) == 0:
        ret = f"N/A"
    elif type is None or type == "None":
        # Guessing mode
        ret = f"{bytes_to_hex(value)}" if len(value) > 8 else f"{bytes_to_int(value)}"
    elif type == "int": # 8 bytes (64bit)
        ret = f"{bytes_to_int(value)}"
    elif type == "hex":
        ret = f"{bytes_to_hex(value)}"
    elif type == "ip":
        tmp = ".".join(f'{c}' for c in value)
        ret = f"{tmp}"
    elif type == "date":
        tmp = format_time(value)
        ret = f"{tmp}"
    elif type == "str":
        tmp = value.decode("utf-8")
        ret = f"{tmp}"
    elif isinstance(type, list):
        ret = ", ".join(unwrap_rlp(value, type, fieldname))
    else:
        ret = f"{bytes_to_hex(value)}"
    return ret

def unwrap_rlp(msg: list, structure: list[tuple[str, str]], fieldname = True) -> list[str]:
    """Creates a flat array of key, values from a dynamically nested msg (i.e. a list with 
    an unknown depth and uneven distribution of sub-lists). The structure is only for providing
    fieldnames, able to be toggled with the fieldname bool

    Args:
        msg (list): The RLP message to be unwrapped
        structure (list[tuple[str, str]]): The structure/fields that are associated with each RLP entry
        fieldname (bool, optional): Whether to append fieldnames to each entry value. Defaults to True.

    Returns:
        list[str]: The flat list of ["<key>: <value>", ...]
    """
    a = []
    def get_leaves(msg: list[bytes] | bytes, structure: list[tuple[str, str]] | tuple[str, str], fieldname = True):
        # base case
        if not isinstance(msg, list) or isinstance(structure, tuple):
            ret = ""
            name = structure[0]
            if name == "" or len(msg) == 0: # Omit empty str name
                return ret
            ret = bytes_to_typestr(msg, structure[1], fieldname)
            if fieldname:
                ret = f"{name}: {ret}"
            a.append(ret)
            return ret
        else: 
            sub = []
            i = 0
            for i in range(len(structure)):
                sub.append(get_leaves(msg[i], structure[i], fieldname))
                i += 1
            return sub
    for i in range(len(structure)):
        get_leaves(msg[i], structure[i], fieldname)
        
    return a

def cleanse_rlp(msg: list) -> list:
    a = [None] * len(msg)
    def get_leaves(msg: list | bytes):
        # base case
        if not isinstance(msg, list):
            if len(msg) == 0:
                return "N/A"
            elif len(msg) <= 8: # 8 bytes (64bit)
                return bytes_to_int(msg)
            else:
                return bytes_to_hex(msg)
        sub = []
        for child in msg:
            sub.append(get_leaves(child))
        return sub
    for i in range(len(msg)):
        a[i] = f"{get_leaves(msg[i])}"
    return a