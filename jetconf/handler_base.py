from typing import Callable, Union

from yangson.schemanode import SchemaNode
from yangson.instance import InstanceRoute

from .journal import DataChange
from .helpers import JsonNodeT


# ---------- Base classes for conf data handlers ----------
class ConfDataHandlerBase:
    def __init__(self, ds: "BaseDatastore", sch_pth: str):
        self.ds = ds
        self.schema_path = sch_pth                          # type: str
        self.schema_node = ds.get_schema_node(sch_pth)      # type: SchemaNode


class ConfDataObjectHandler(ConfDataHandlerBase):
    def create(self, ii: InstanceRoute, ch: DataChange):
        pass

    def replace(self, ii: InstanceRoute, ch: DataChange):
        pass

    def delete(self, ii: InstanceRoute, ch: DataChange):
        pass

    def __str__(self):
        return self.__class__.__name__ + ": listening at " + self.schema_path


class ConfDataListHandler(ConfDataHandlerBase):
    def create_item(self, ii: InstanceRoute, ch: DataChange):
        pass

    def replace_item(self, ii: InstanceRoute, ch: DataChange):
        pass

    def delete_item(self, ii: InstanceRoute, ch: DataChange):
        pass

    def create_list(self, ii: InstanceRoute, ch: DataChange):
        pass

    def replace_list(self, ii: InstanceRoute, ch: DataChange):
        pass

    def delete_list(self, ii: InstanceRoute, ch: DataChange):
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


# ---------- Types ----------
ConfDataHandler = Union[ConfDataObjectHandler, ConfDataListHandler]
StateDataHandler = Union[StateDataContainerHandler, StateDataListHandler]
OpHandler = Callable[[JsonNodeT, str], JsonNodeT]
ActionHandler = Callable[[InstanceRoute, JsonNodeT, str], JsonNodeT]
