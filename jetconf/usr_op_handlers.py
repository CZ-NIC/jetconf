from colorlog import info

from .helpers import JsonNodeT
from .handler_list import OP_HANDLERS
from .data import BaseDatastore


# ---------- User-defined handlers follow ----------

class OpHandlersContainer:
    def __init__(self, ds: BaseDatastore):
        self.ds = ds

    def jukebox_play_op(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        # Structure of RPC's input and output arguments is defined in YANG data model
        # Do something
        info("Called operation 'jukebox_play_op' by user '{}':".format(username))
        info("Playlist name: {}".format(input_args["example-jukebox:playlist"]))
        info("Song number: {}".format(input_args["example-jukebox:song-number"]))


def register_op_handlers(ds: BaseDatastore):
    op_handlers_obj = OpHandlersContainer(ds)
    OP_HANDLERS.register(op_handlers_obj.jukebox_play_op, "example-jukebox:play")
