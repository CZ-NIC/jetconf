from typing import List, Tuple, Callable, Any
from yangson.context import Context
from yangson.schema import SchemaNode

HandlerSelectorT = Any


class BaseHandlerList:
    def __init__(self):
        self.handlers = []              # type: List[Tuple[HandlerSelectorT, Callable]]
        self.default_handler = None     # type: Callable

    def register_handler(self, identifier: str, handler: Callable):
        raise NotImplementedError("Not implemented in base class")

    def register_default_handler(self, handler: Callable):
        self.default_handler = handler

    def get_handler(self, identifier: str) -> Callable:
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

    def get_handler(self, sch_node_id: str) -> Callable:
        for h in self.handlers:
            if h[0] == sch_node_id:
                return h[1]

        return None


class StateDataHandlerList:
    def __init__(self):
        self.handlers = []

    def register_handler(self, handler: "StateNodeHandlerBase"):
        saddr = Context.path2route(handler.sch_pth)
        self.handlers.append((saddr, handler))

    def get_handler(self, sch_pth: str, allow_superior: bool = True) -> Callable:
        saddr = Context.path2route(sch_pth)
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
