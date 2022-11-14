
from pydevp2p.utils import bytes_to_hex, bytes_to_int


def deserialize_rlp(msg: list, structure: list) -> list:
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
        a[i] = f"{structure[i]}: {get_leaves(msg[i])}"
    return a
    
def get_shape(msg: list):
    a = [None] * len(msg)
    def get_leaves(msg: list | bytes):
        # base case
        if not isinstance(msg, list):
            return 1
        count = 0
        for child in msg:
            count = count + get_leaves(child)
        return count
    for i in range(len(msg)):
        a[i] = get_leaves(msg[i])
    return a