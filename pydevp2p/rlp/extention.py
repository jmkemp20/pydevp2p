from typing import Any
from rlp.sedes import Serializable
from pydevp2p.utils import dict_to_depth_str_list, flatten_dict


class RLPMessage(Serializable):

    def as_dict(self, parent_field=None, flat=False) -> dict[str, Any]:
        # allows for deep dictionary casting
        ret = {}

        def parse_tuple(seq: tuple, parent_field: str):
            ret2 = {}
            for index, val in enumerate(seq):
                new_field = f"{parent_field}_#{index+1}"
                if isinstance(val, RLPMessage):
                    ret2[new_field] = val.as_dict(
                        parent_field=(new_field if flat else None), flat=flat)
                elif isinstance(val, Serializable):
                    ret2[new_field] = val.as_dict()
                elif isinstance(val, tuple):
                    ret2[new_field] = parse_tuple(
                        val, new_field)
                else:
                    ret2[new_field] = "N/A" if val == "" or val == None else val
            return ret2

        for field, value in zip(self._meta.field_names, self):
            new_field = field if parent_field is None or not flat else f"{parent_field}_#{field}"
            if isinstance(value, RLPMessage):
                ret[new_field] = value.as_dict(
                    parent_field=new_field, flat=flat)
            elif isinstance(value, Serializable):
                ret[new_field] = value.as_dict()
            elif isinstance(value, tuple):
                ret[new_field] = parse_tuple(value, new_field)
            elif isinstance(value, dict):
                pass
            else:
                ret[new_field] = "N/A" if value == "" or value == None else value
        return ret

    def as_flat_dict(self) -> dict[str, Any]:
        return flatten_dict(self.as_dict(flat=True))

    def as_str_list(self) -> list[str]:
        return dict_to_depth_str_list(self.as_dict())


# https://www.programcreek.com/python/?code=ethereum%2Fpy-evm%2Fpy-evm-master%2Feth%2F_utils%2Frlp.py#
