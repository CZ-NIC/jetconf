from datetime import datetime
from enum import Enum

from typing import Dict, List, Any
from hashlib import sha1
from jetconf.yang_json_path import BasePath


class YangNodeType(Enum):
    UNKNOWN = 0
    CONTAINER = 1
    LIST = 2
    LEAF_LIST = 3
    LEAF = 4
    ANYDATA = 5
    ANYXML = 6


class YangDataType(Enum):
    UNKNOWN = 0
    STRING = 1
    BOOLEAN = 2
    ENUM = 2
    BITS = 3
    BINARY = 4
    LEAFREF = 5
    IDENTITYREF = 6
    EMPTY = 7
    UNION = 8
    INSTANCE_ID = 9
    INT8 = 10
    INT16 = 11
    INT32 = 12
    INT64 = 13
    UINT8 = 14
    UINT16 = 15
    UINT32 = 16
    UINT64 = 17


class JsonDoc:
    def __init__(self):
        self.root = None                # type: JsonNodeObject
        self.root_prefix_path = None    # type: BasePath


class JsonNode:
    def __init__(self):
        self.parent = None          # type: JsonNode
        self.last_modified = None   # type: datetime
        self.etag = None            # type: str
        self.yang_node_type = None  # type: YangNodeType

    def _update_etag(self):
        self.last_modified = datetime.now()
        etag_data = str(id(self)) + str(self.last_modified)
        sha_obj = sha1()
        sha_obj.update(etag_data.encode())
        self.etag = sha_obj.hexdigest()


class JsonNodeList(JsonNode):
    def __init__(self):
        super().__init__()
        self.children = []          # type: List[JsonNode]

    def append(self, item: JsonNode):
        self.children.append(item)
        self._update_etag()

    def pop(self, i: int) -> JsonNode:
        n = self.children.pop(i)
        self._update_etag()
        return n


class JsonNodeObject(JsonNode):
    def __init__(self):
        super().__init__()
        self.children = {}          # type: Dict[JsonNode]

    def add_child(self, key: str, val: JsonNode):
        self.children[key] = val
        self._update_etag()

    def remove_child(self, key: str):
        try:
            del self.children[key]
            self._update_etag()
        except KeyError:
            pass


class JsonNodeLeaf(JsonNode):
    def __init__(self):
        super().__init__()
        self.yang_leaf_type = None  # type: YangDataType
        self._value = None          # type: str, numeric or bool

    def set_value(self, val: Any):
        self._value = val
        self._update_etag()

    def get_value(self) -> Any:
        return self._value
