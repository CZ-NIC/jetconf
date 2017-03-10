from typing import List, Tuple, Callable, Any
from yangson.schema import SchemaNode
from yangson.schemadata import SchemaData
from yangson.instance import InstanceRoute

HandlerSelectorT = Any


class ConfDataObjectHandler:
    def __init__(self, ds: "BaseDatastore", sch_pth: str):
        self.ds = ds
        self.schema_path = sch_pth                          # type: str
        self.schema_node = ds.get_schema_node(sch_pth)      # type: SchemaNode

    def create(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def replace(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def delete(self, ii: InstanceRoute, ch: "DataChange"):
        pass

    def __str__(self):
        return self.__class__.__name__ + ": listening at " + self.schema_path


class ConfDataListHandler:
    def __init__(self, ds: "BaseDatastore", sch_pth: str):
        self.ds = ds
        self.schema_path = sch_pth                          # type: str
        self.schema_node = ds.get_schema_node(sch_pth)      # type: SchemaNode

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


class BaseHandlerList:
    def __init__(self):
        self.handlers = []              # type: List[Tuple[HandlerSelectorT, Callable]]
        self.default_handler = None     # type: Callable

    def register_handler(self, identifier: str, handler: Callable):
        raise NotImplementedError("Not implemented in base class")

    def register_default_handler(self, handler: Callable):
        self.default_handler = handler

    def get_handler(self, identifier: str) -> Any:
        raise NotImplementedError("Not implemented in base class")


class OpHandlerList(BaseHandlerList):
    def register_handler(self, op_name: str, handler: Callable):
        self.handlers.append((op_name, handler))

    def get_handler(self, op_name: str) -> Callable:
        for h in self.handlers:
            if h[0] == op_name:
                return h[1]

        return self.default_handler


class ConfDataHandlerList:
    def __init__(self):
        self.handlers = []  # type: List[Tuple[HandlerSelectorT, BaseDataListener]]

    def register_handler(self, handler: "BaseDataListener"):
        schema_node = handler.schema_node  # type: SchemaNode
        sch_node_id = str(id(schema_node))
        self.handlers.append((sch_node_id, handler))

    def get_handler(self, sch_node_id: str) -> "BaseDataListener":
        for h in self.handlers:
            if h[0] == sch_node_id:
                return h[1]

        return None


class StateDataHandlerList:
    def __init__(self):
        self.handlers = []

    def register_handler(self, handler: "StateNodeHandlerBase"):
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


OP_HANDLERS = OpHandlerList()
STATE_DATA_HANDLES = StateDataHandlerList()
CONF_DATA_HANDLES = ConfDataHandlerList()
