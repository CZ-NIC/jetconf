from enum import Enum
from typing import Dict, Any
from datetime import datetime
from pytz import timezone
from yangson.instance import InstanceRoute, MemberName, EntryKeys, InstanceIdParser, ResourceIdParser
from yangson.datamodel import DataModel


class PathFormat(Enum):
    URL = 0
    XPATH = 1


class CertHelpers:
    @staticmethod
    def get_field(cert: Dict[str, Any], key: str) -> str:
            return ([x[0][1] for x in cert["subject"] if x[0][0] == key] or [None])[0]


class DataHelpers:
    # Create parent data nodes to JSON subtree up to top level
    @staticmethod
    def node2doc(id: InstanceRoute, val: Any) -> Dict[str, Any]:
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

    @staticmethod
    def path_first_ns(api_pth: str) -> str:
        return api_pth[1:].split("/", maxsplit=1)[0].split(":", maxsplit=1)[0]

    @staticmethod
    def load_data_model(module_dir: str, yang_library_file: str) -> DataModel:
        with open(yang_library_file) as ylfile:
            yl = ylfile.read()
        dm = DataModel(yl, [module_dir])
        return dm

    # Parse Instance Identifier from string
    @staticmethod
    def parse_ii(path: str, path_format: PathFormat) -> InstanceRoute:
        if path_format == PathFormat.URL:
            ii = ResourceIdParser(path).parse()
        else:
            ii = InstanceIdParser(path).parse()

        return ii


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
    def epretty(e: BaseException, module_name: str=None) -> str:
        err_str = e.__class__.__name__ + ": " + str(e)
        if module_name is not None:
            return "In module " + module_name + ": " + err_str
        else:
            return err_str
