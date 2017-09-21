from typing import Dict, Callable

from yangson.schemanode import SchemaNode
from yangson.schemadata import SchemaData
from yangson.instance import InstanceRoute

from .helpers import JsonNodeT


# ---------- Base classes for conf data handlers ----------
class ConfDataHandlerBase:
    def __init__(self, ds: "BaseDatastore", sch_pth: str):
        self.ds = ds
        self.schema_path = sch_pth                          # type: str
        self.schema_node = ds.get_schema_node(sch_pth)      # type: SchemaNode


class ConfDataObjectHandler(ConfDataHandlerBase):
    def create(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def replace(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def delete(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def __str__(self):
        return self.__class__.__name__ + ": listening at " + self.schema_path


class ConfDataListHandler(ConfDataHandlerBase):
    def create_item(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def replace_item(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def delete_item(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def create_list(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def replace_list(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def delete_list(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def __str__(self):
        return self.__class__.__name__ + ": listening at " + self.schema_path


# ---------- Base classes for state data handlers ----------
class StateDataHandlerBase:
    def __init__(self, datastore: "BaseDatastore", schema_path: str):
        self.ds = datastore
        self.data_model = datastore.get_dm()
        self.sch_pth = schema_path
        self.schema_node = self.data_model.get_data_node(self.sch_pth)


class StateDataContainerHandler(StateDataHandlerBase):
    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        pass


class StateDataListHandler(StateDataHandlerBase):
    def generate_list(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        pass

    def generate_item(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        pass


# ---------- Handler lists ----------
class ConfDataHandlerList:
    def __init__(self):
        self.handlers = {}  # type: Dict[int, ConfDataHandlerBase]
        self.handlers_pth = {}  # type: Dict[str, ConfDataHandlerBase]

    def register(self, handler: ConfDataHandlerBase):
        sch_node_id = id(handler.schema_node)
        self.handlers[sch_node_id] = handler
        self.handlers_pth[handler.schema_path] = handler

    def get_handler(self, sch_node_id: int) -> ConfDataHandlerBase:
        return self.handlers.get(sch_node_id)

    def get_handler_by_pth(self, sch_pth: str) -> ConfDataHandlerBase:
        return self.handlers_pth.get(sch_pth)


class StateDataHandlerList:
    def __init__(self):
        self.handlers = []

    def register(self, handler: "StateDataHandlerBase"):
        saddr = SchemaData.path2route(handler.sch_pth)
        self.handlers.append((saddr, handler))

    def get_handler(self, sch_pth: str, allow_superior: bool = True) -> Callable:
        saddr = SchemaData.path2route(sch_pth)
        if allow_superior:
            while saddr:
                for h in self.handlers:
                    if h[0] == saddr:
                        return h[1]
                saddr.pop()
        else:
            for h in self.handlers:
                if h[0] == saddr:
                    return h[1]

        return None


class OpHandlerList:
    def __init__(self):
        self.handlers = {}  # type: Dict[str, Callable]
        self.default_handler = None  # type: Callable

    def register(self, handler: Callable, op_name: str):
        self.handlers[op_name] = handler

    def register_default(self, handler: Callable):
        self.default_handler = handler

    def get_handler(self, op_name: str) -> Callable:
        return self.handlers.get(op_name, self.default_handler)


# ---------- Handler list globals ----------
OP_HANDLERS = OpHandlerList()
STATE_DATA_HANDLES = StateDataHandlerList()
CONF_DATA_HANDLES = ConfDataHandlerList()
