from typing import List, Tuple, Callable, Any
from .data import BaseDatastore, PathFormat
from yangson.context import Context

HandlerSelectorT = Any


class BaseHandlerList:
    def __init__(self):
        self.handlers = []              # type: List[Tuple[HandlerSelectorT, Callable]]
        self.default_handler = None     # type: Callable

    def register_handler(self, name: str, handler: Callable):
        raise NotImplementedError("Not implemented in base class")

    def register_default_handler(self, handler: Callable):
        self.default_handler = handler

    def get_handler(self, name: str) -> Callable:
        raise NotImplementedError("Not implemented in base class")


class OpHandlerList(BaseHandlerList):
    def register_handler(self, name: str, handler: Callable):
        self.handlers.append((name, handler))

    def get_handler(self, name: str) -> Callable:
        for h in self.handlers:
            if h[0] == name:
                return h[1]

        return self.default_handler


class StateDataHandlerList:
    def __init__(self):
        self.handlers = []
        self.ds = None      # type: BaseDatastore

    # def register_handler(self, ii_str: str, handler: Callable):
    #     ii = self.ds.parse_ii(ii_str, PathFormat.XPATH)
    #     self.handlers.append((ii, handler))
    #
    # def get_handler(self, ii: InstanceIdentifier, allow_superior: bool=True) -> Callable:
    #     if allow_superior:
    #         ii_local = ii.copy()
    #         while ii_local:
    #             dn = self.ds.get_node(ii_local)
    #             for h in self.handlers:
    #                 if self.ds.get_node(h[0]).value is dn.value:
    #                     return h[1]
    #             ii_local.pop()
    #     else:
    #         for h in self.handlers:
    #             if h[0] == ii:
    #                 return h[1]
    #
    #     return self.default_handler

    def register_handler(self, handler):
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

    # def set_ds(self, ds: BaseDatastore):
    #     self.ds = ds


OP_HANDLERS = OpHandlerList()
STATE_DATA_HANDLES = StateDataHandlerList()
