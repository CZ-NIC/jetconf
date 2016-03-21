import json
import logging
from threading import Lock

import colorlog
import sys
from enum import Enum
from colorlog import error, warning as warn, info, debug
from typing import List, Any, Dict, TypeVar, Tuple, Set
import copy
import yangson.instance
from yangson.instance import Instance, NonexistentInstance, InstanceError, ArrayValue, ObjectValue, MemberName, EntryKeys, EntryIndex
from yangson import DataModel
from yangson.datamodel import InstanceIdentifier
from .helpers import DataHelpers


class PathFormat(Enum):
    URL = 0
    XPATH = 1


class NacmForbiddenError(Exception):
    def __init__(self, msg="Access to data node rejected by NACM"):
        self.msg = msg


class DataLockError(Exception):
    def __init__(self, msg=""):
        self.msg = msg


class InstanceAlreadyPresent(InstanceError):
    pass


class Rpc:
    def __init__(self):
        self.username = None    # type: str
        self.path = None        # type: str
        self.path_format = PathFormat.URL  # type: PathFormat


class BaseDatastore:
    def __init__(self, module_dir: str, yang_library_file: str, name: str=""):
        self.name = name
        self.nacm = None    # type: NacmConfig
        self._data = None   # type: Instance
        self._dm = None     # type: DataModel
        self._data_lock = Lock()
        self._lock_username = None  # type: str

        with open(yang_library_file) as ylfile:
            yl = ylfile.read()
        self._dm = DataModel.from_yang_library(yl, module_dir)

    # Register NACM module to datastore
    def register_nacm(self, nacm_config: "NacmConfig"):
        self.nacm = nacm_config

    # Returns the root node of data tree
    def get_data_root(self) -> Instance:
        return self._data

    # Parse Instance Identifier from string
    def parse_ii(self, path: str, path_format: PathFormat) -> InstanceIdentifier:
        if path_format == PathFormat.URL:
            ii = self._dm.parse_resource_id(path)
        else:
            ii = self._dm.parse_instance_id(path)

        return ii

    # Just get the node, do not evaluate NACM (for testing purposes)
    def get_node(self, ii: InstanceIdentifier) -> Instance:
        n = self._data.goto(ii)
        return n

    # Just get the node, do not evaluate NACM (for testing purposes)
    def get_node_path(self, path: str, path_format: PathFormat) -> Instance:
        ii = self.parse_ii(path, path_format)
        n = self._data.goto(ii)
        return n

    # Get data node, evaluate NACM if possible
    def get_node_rpc(self, rpc: Rpc) -> Instance:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = self._data.goto(ii)

        if self.nacm:
            nrpc = NacmRpc(self.nacm, self, rpc.username)
            if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prun subtree data
                n = nrpc.check_data_read_path(ii)

        return n

    def create_node_rpc(self, rpc: Rpc, value: Any, insert=None, point=None):
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = self._data.goto(ii)

        # if self.nacm:
        #     nrpc = NacmRpc(self.nacm, self, rpc.username)
        #     if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ) == Action.DENY:
        #         raise NacmForbiddenError()
        #     else:
        #         # Prun subtree data
        #         n = nrpc.check_data_read_path(ii)

        value_keys = value.keys()
        if len(value_keys) > 1:
            raise ValueError("Received data containing more than one instance")

        val_key = tuple(value_keys)[0]
        val_data = value[val_key]

        existing_member = None
        try:
            existing_member = n.member(val_key)
        except NonexistentInstance:
            pass

        if existing_member is None:
            # Create new data node
            data_doc = DataHelpers.node2doc(ii + [MemberName(val_key)], val_data)
            data_doc_inst = self._dm.from_raw(data_doc)
            new_value = data_doc_inst.goto(ii).value

            new_value_data = new_value[val_key]

            new_n = n.new_member(val_key, new_value_data)
            self._data = new_n.top()
        elif isinstance(existing_member.value, ArrayValue):
            # Append received node to list
            data_doc = DataHelpers.node2doc(ii + [MemberName(val_key)], [val_data])
            data_doc_inst = self._dm.from_raw(data_doc)
            new_value = data_doc_inst.goto(ii).value

            new_value_data = new_value[val_key][0]

            if insert == "first":
                new_n = existing_member.update(ArrayValue(val=[new_value_data] + existing_member.value))
            else:
                new_n = existing_member.update(ArrayValue(val=existing_member.value + [new_value_data]))
            self._data = new_n.top()
        else:
            raise InstanceAlreadyPresent("InstanceAlreadyPresent")

        if not isinstance(n.value, ObjectValue):
            error("create_node: target resource not an object")

    def put_node_rpc(self, rpc: Rpc, value: Any):
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = self._data.goto(ii)

        # if self.nacm:
        #     nrpc = NacmRpc(self.nacm, self, rpc.username)
        #     if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ) == Action.DENY:
        #         raise NacmForbiddenError()
        #     else:
        #         # Prun subtree data
        #         n = nrpc.check_data_read_path(ii)

        value_keys = value.keys()
        if len(value_keys) > 1:
            raise ValueError("Received data containing more than one instance")

        inst_val = tuple(value_keys)[0]

        new_n = n.update(inst_val)
        self._data = new_n.top()

    def delete_node_rpc(self, rpc: Rpc, insert=None, point=None):
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = self._data.goto(ii)
        n_parent = n.up()
        last_isel = ii[-1]

        # if self.nacm:
        #     nrpc = NacmRpc(self.nacm, self, rpc.username)
        #     if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ) == Action.DENY:
        #         raise NacmForbiddenError()
        #     else:
        #         # Prun subtree data
        #         n = nrpc.check_data_read_path(ii)

        if isinstance(last_isel, EntryIndex):
            new_n = n_parent.remove_entry(last_isel.index)
        elif isinstance(last_isel, EntryKeys):
            new_n = n_parent.remove_entry(n.crumb.pointer_fragment())
        elif isinstance(last_isel, MemberName):
            new_n = n_parent.remove_member(last_isel.name)

        self._data = new_n.top()

    # Locks datastore data
    def lock_data(self, username: str = None, blocking: bool=True):
        ret = self._data_lock.acquire(blocking=blocking, timeout=1)
        if ret:
            self._lock_username = username or "(unknown)"
            info("Acquired lock in datastore \"{}\" for user \"{}\"".format(self.name, username))
        else:
            raise DataLockError(
                    "Failed to acquire lock in datastore \"{}\" for user \"{}\", already locked by \"{}\"".format(
                            self.name,
                            username,
                            self._lock_username
                    )
            )

    # Unlocks datastore data
    def unlock_data(self):
        self._data_lock.release()
        info("Released lock in datastore \"{}\" for user \"{}\"".format(self.name, self._lock_username))
        self._lock_username = None

    # Loads the data from file
    def load(self, filename: str):
        raise NotImplementedError("Not implemented in base class")

    # Saves the data to file
    def save(self, filename: str):
        raise NotImplementedError("Not implemented in base class")


class JsonDatastore(BaseDatastore):
    def load(self, filename: str):
        self._data = None
        with open(filename, "rt") as fp:
            self._data = self._dm.from_raw(json.load(fp))

    def save(self, filename: str):
        with open(filename, "w") as jfd:
            self.lock_data("json_save")
            json.dump(self._data, jfd)
            self.unlock_data()


def test():
    data = JsonDatastore("./data", "./data/yang-library-data.json")
    data.load("jetconf/example-data.json")

    rpc = Rpc()
    rpc.username = "dominik"
    rpc.path = "/dns-server:dns-server/zones/zone[domain='example.com']/query-module"
    rpc.path_format = PathFormat.XPATH

    info("Reading: " + rpc.path)
    n = data.get_node_rpc(rpc)
    info("Result =")
    print(n.value)
    if json.loads(json.dumps(n.value)) == [{'name': 'test1', 'type': 'knot-dns:synth-record'}, {'name': 'test2', 'type': 'knot-dns:synth-record'}]:
        info("OK")
    else:
        warn("FAILED")

from .nacm import NacmConfig, NacmRpc, Permission, Action
