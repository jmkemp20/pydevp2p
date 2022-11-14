
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
        return f"RLPxCapabilityMsg:\n{ret}"
    
    def getValues(self):
        return [0]