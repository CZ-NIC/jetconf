from typing import List, Dict, Tuple

from yangson.datamodel import DataModel
from yangson.schemadata import SchemaData
from yangson.typealiases import SchemaRoute

from .handler_base import ConfDataHandlerBase, StateDataHandlerBase, ConfDataHandler, StateDataHandler, OpHandler, ActionHandler


# ---------- Handler lists ----------
class ConfDataHandlerList:
    def __init__(self):
        self.handlers = {}  # type: Dict[int, ConfDataHandlerBase]
        self.handlers_pth = {}  # type: Dict[str, ConfDataHandlerBase]

    def register(self, handler: ConfDataHandlerBase):
        sch_node_id = id(handler.schema_node)
        self.handlers[sch_node_id] = handler
        self.handlers_pth[handler.schema_path] = handler

    def get_handler(self, sch_node_id: int) -> ConfDataHandler:
        return self.handlers.get(sch_node_id)

    def get_handler_by_pth(self, sch_pth: str) -> ConfDataHandler:
        return self.handlers_pth.get(sch_pth)


class StateDataHandlerList:
    def __init__(self):
        self.handlers = []  # type: List[Tuple[SchemaRoute, StateDataHandlerBase]]

    def register(self, handler: StateDataHandlerBase):
        saddr = SchemaData.path2route(handler.sch_pth)
        self.handlers.append((saddr, handler))

    def get_handler(self, sch_pth: str, allow_superior: bool = True) -> StateDataHandler:
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
        self.handlers = {}  # type: Dict[str, OpHandler]

    def register(self, handler: OpHandler, op_name: str):
        self.handlers[op_name] = handler

    def get_handler(self, op_name: str) -> OpHandler:
        return self.handlers.get(op_name)


class ActionHandlerList:
    def __init__(self, dm: DataModel):
        self.handlers = {}  # type: Dict[int, ActionHandler]
        self._dm = dm

    def register(self, handler: ActionHandler, sch_pth: str):
        sn = self._dm.get_schema_node(sch_pth)
        self.handlers[id(sn)] = handler

    def get_handler(self, sch_node_id: int) -> ActionHandler:
        return self.handlers.get(sch_node_id)
