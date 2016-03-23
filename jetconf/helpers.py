from typing import Dict, Any
from datetime import datetime
from pytz import timezone
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


class DateTimeHelpers:
    @staticmethod
    def to_httpdate_str(dt: datetime, local_tz: str=None) -> str:
        if local_tz is not None:
            dtl = timezone(local_tz).localize(dt)
            dt_gmt = dtl.astimezone(timezone("GMT"))
        else:
            dt_gmt = dt

        return dt_gmt.strftime("%a, %d %b %Y %H:%M:%S GMT")


class ErrorHelpers:
    @staticmethod
    def epretty(e: BaseException) -> str:
        return e.__class__.__name__ + ": " + str(e)
