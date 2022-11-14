from pydevp2p.utils import bytes_to_hex, bytes_to_int


class RLPxCapabilityMsg:
    """
    _summary
    """
    def __init__(self, msg: list[bytes]) -> None:
        self.msg = msg
        return
    
            
    def __str__(self) -> str:
        ret = ""
        vals = self.getValues()
        for i in range(1, len(vals)):
            ret += f"  {vals[i]}\n"
        return f"RLPxCapabilityMsg:\n  {self.msg}"
    
    def getValues(self):
        return [0]
    
class EthCapabilitiy(RLPxCapabilityMsg):
    """_summary_

    Args:
        RLPxCapabilityMsg (_type_): _description_
    """
    # Type structures
    ForkId = ["Fork Hash", "Fork Next"]
    Status = ["Version", "Network ID", "Total Difficulty", "Block Hash", "Genesis", ForkId]
    def __init__(self, msg: list[bytes]) -> None:
        super().__init__(msg)
        self.isStatus = get_shape(msg) == get_shape(self.Status)
    
def get_rlpx_capability_msg(msg: list[bytes]) -> RLPxCapabilityMsg:
    for field in msg:
        if isinstance(field, list):
            print()
        elif len(field) == 0:
            print("N/A")
        elif len(field) <= 4:
            print(field, bytes_to_int(field))
        else:
            print(bytes_to_hex(field))
            
    print(EthCapabilitiy(msg).isStatus)
    print(get_shape(msg), get_shape(EthCapabilitiy(msg).Status))
    print(get_shape([0, 2, [1, 2, [1, [3, 4], 5], 6, [7, 8, 9]], [6, [6, [8, [7, 9]], [8]], [9, [10]]]]))
    
    return RLPxCapabilityMsg(msg)


    
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
    

    