from colorlog import info
from typing import List, Dict, Union, Any

from yangson.instance import InstanceRoute
from .data import BaseDatastore, DataChange
from .helpers import ErrorHelpers, LogHelpers
from .handler_list import CONF_DATA_HANDLES, ConfDataObjectHandler, ConfDataListHandler

JsonNodeT = Union[Dict[str, Any], List]
epretty = ErrorHelpers.epretty
debug_confh = LogHelpers.create_module_dbg_logger(__name__)


# ---------- User-defined handlers follow ----------


class JukeboxExampleConfHandler(ConfDataListHandler):
    def create_item(self, ii: InstanceRoute, ch: "DataChange"):
        debug_confh(self.__class__.__name__ + " replace triggered")
        info("Creating item '/example-jukebox:jukebox/library/artist' in app configuration")

    def create_list(self, ii: InstanceRoute, ch: "DataChange"):
        debug_confh(self.__class__.__name__ + " replace triggered")
        info("Creating list '/example-jukebox:jukebox/library/artist' in app configuration")

    def replace_item(self, ii: InstanceRoute, ch: "DataChange"):
        debug_confh(self.__class__.__name__ + " replace triggered")
        info("Replacing item '/example-jukebox:jukebox/library/artist' in app configuration")

    def replace_list(self, ii: InstanceRoute, ch: "DataChange"):
        debug_confh(self.__class__.__name__ + " replace triggered")
        info("Replacing list '/example-jukebox:jukebox/library/artist' in app configuration")

    def delete_item(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " delete triggered")
        info("Deleting item '/example-jukebox:jukebox/library/artist' from app configuration")

    def delete_list(self, ii: InstanceRoute, ch: "DataChange"):
        debug_confh(self.__class__.__name__ + " delete triggered")
        info("Deleting list '/example-jukebox:jukebox/library/artist' from app configuration")


def register_conf_handlers(ds: BaseDatastore):
    CONF_DATA_HANDLES.register(JukeboxExampleConfHandler(ds, "/example-jukebox:jukebox/library/artist"))
