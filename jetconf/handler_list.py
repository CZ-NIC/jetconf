from typing import List, Tuple, Callable


class OpHandlerList:
    def __init__(self):
        self.handlers = []              # type: List[Tuple[str, Callable]]
        self.default_handler = None     # type: Callable

    def register_handler(self, name: str, handler: Callable):
        self.handlers.append((name, handler))

    def register_default_handler(self, handler: Callable):
        self.default_handler = handler

    def get_handler(self, name: str) -> Callable:
        for h in self.handlers:
            if h[0] == name:
                return h[1]

        return self.default_handler


OP_HANDLERS = OpHandlerList()
