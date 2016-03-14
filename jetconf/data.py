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
from yangson.instance import Instance, NonexistentInstance, ArrayValue, ObjectValue
from yangson import DataModel
from yangson.datamodel import InstanceIdentifier


class PathFormat(Enum):
    URL = 0
    XPATH = 1


class NacmForbiddenError(Exception):
    def __init__(self, msg="Access to data node rejected by NACM"):
        self.msg = msg


class DataLockError(Exception):
    def __init__(self, msg=""):
        self.msg = msg


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

    # Just get the node, do not evaluate NACM (for testing purposes)
    def get_node(self, ii: InstanceIdentifier) -> Instance:
        # self.lock_data("get_node")
        n = self._data.goto(ii)
        # self.unlock_data()
        return n

    # Just get the node, do not evaluate NACM (for testing purposes)
    def get_node_path(self, path: str, path_format: PathFormat) -> Instance:
        n = None
        if path_format == PathFormat.URL:
            ii = self._dm.parse_resource_id(path)
        else:
            ii = self._dm.parse_instance_id(path)

        # self.lock_data("get_node_path")
        n = self._data.goto(ii)
        # self.unlock_data()
        return n

    # Get data node, evaluate NACM if possible
    def get_node_rpc(self, rpc: Rpc) -> Instance:
        n = None
        if rpc.path_format == PathFormat.URL:
            ii = self._dm.parse_resource_id(rpc.path)
        else:
            ii = self._dm.parse_instance_id(rpc.path)
        # self.lock_data(rpc.username)
        n = self._data.goto(ii)
        # self.unlock_data()

        if self.nacm:
            nrpc = NacmRpc(self.nacm, self, rpc.username)
            if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prun subtree data
                n = nrpc.check_data_read_path(ii)

        return n

    # Locks datastore data
    def lock_data(self, username: str = None):
        ret = self._data_lock.acquire(blocking=False)
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
    """
    with open("./data/yang-library-data.json") as ylfile:
        yl = ylfile.read()
    _dm = DataModel.from_yang_library(yl, "./data")
    with open("jetconf/example-data.json", "rt") as fp:
        _root = _dm.from_raw(json.load(fp))
    print(hash(_root.member("dns-server:dns-server").value))
    """

    # exit()
    data = JsonDatastore("./data", "./data/yang-library-data.json")
    data.load("jetconf/example-data.json")

    rpc = Rpc()
    rpc.username = "dominik"
    rpc.path = "/dns-server:dns-server/zones/zone[domain='example.com']/query-module"
    rpc.path_format = PathFormat.XPATH

    n = data.get_node_rpc(rpc)
    print(n.value)
    print(hash(data.get_data_root().member("dns-server:dns-server").value))


from .nacm import NacmConfig, NacmRpc, Permission, Action
