from enum import Enum
from colorlog import error, warning as warn, info

from .helpers import JsonNodeT
from .handler_list import OP_HANDLERS


class KnotZoneCmd(Enum):
    SET = 0
    UNSET = 1


class KnotOp:
    def __init__(self, cmd: KnotZoneCmd, op_input: JsonNodeT):
        self.cmd = cmd
        self.op_input = op_input


class OpHandlersContainer:
    def __init__(self):
        pass

    def jukebox_play_op(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        # Structure of RPC's input and output arguments is defined in YANG data model
        # Do something
        info("Called operation 'jukebox_play_op' by user '{}':".format(username))
        info("Playlist name: {}".format(input_args["example-jukebox:playlist"]))
        info("Song number: {}".format(input_args["example-jukebox:song-number"]))


OP_HANDLERS_IMPL = OpHandlersContainer()


def register_op_handlers():
    OP_HANDLERS.register(OP_HANDLERS_IMPL.jukebox_play_op, "example-jukebox:play")
