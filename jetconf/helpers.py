from typing import Dict, Any
from yangson.instance import InstanceIdentifier, MemberName, EntryKeys


class CertHelpers:
    @staticmethod
    def get_field(cert: Dict[str, Any], key: str) -> str:
            return ([x[0][1] for x in cert["subject"] if x[0][0] == key] or [None])[0]


class DataHelpers:
    # Create parent data nodes to JSON subtree up to top level
    @staticmethod
    def node2doc(id: InstanceIdentifier, val: Any) -> Dict[str, Any]:
        n = val
        for isel in reversed(id):
            if isinstance(isel, MemberName):
                new_node = {}
                new_node[isel.name] = n
                n = new_node
            if isinstance(isel, EntryKeys):
                new_node = []
                for k in isel.keys:
                    n[k] = isel.keys[k]
                new_node.append(n)
                n = new_node
        return n
