import json
import logging
from threading import Lock

import colorlog
import sys
from enum import Enum, unique
from colorlog import error, warning as warn, info, debug
from typing import List, Any, Dict, TypeVar, Tuple, Set
import copy
import yangson.instance
from yangson.instance import Instance, NonexistentInstance, ArrayValue, ObjectValue
from yangson import DataModel
from yangson.datamodel import InstanceIdentifier
from nacm import Permission, Action
from nacm import NacmConfig, NacmRpc


class Rpc:
    def __init__(self):
        self.username = None
        self.path = None    # type: str


class BaseDatastore:
    def __init__(self, module_dir: str, yang_library_file: str):
        self.data = None    # type: Instance
        self.dm = None      # type: DataModel
        self.nacm = None    # type: NacmConfig
        self._data_lock = Lock()
        self._lock_username = None

        with open(yang_library_file) as ylfile:
            yl = ylfile.read()
        self.dm = DataModel.from_yang_library(yl, module_dir)

    def register_nacm(self, nacm_config: NacmConfig):
        self.nacm = nacm_config

    def get_data_root(self) -> Instance:
        return self.data

    def get_node(self, ii: InstanceIdentifier) -> Instance:
        return self.data.goto(ii)

    def get_node_path(self, ii_str: str) -> Instance:
        ii = self.dm.parse_instance_id(ii_str)
        return self.data.goto(ii)

    def get_node_rpc(self, rpc: Rpc) -> Instance:
        n = None
        ii = self.dm.parse_instance_id(rpc.path)
        self.lock_data(rpc.username)
        n = self.data.goto(ii)
        self.unlock_data()

        if self.nacm:
            nrpc = NacmRpc(self.nacm, None, rpc.username)
            if nrpc.check_data_node(n, Permission.NACM_ACCESS_READ) == Action.DENY:
                return None
            else:
                # Prun subtree data
                n = nrpc.check_data_read(n)

        return n

    def lock_data(self, username: str = None):
        res = self._data_lock.acquire(blocking=False)
        if res:
            self._lock_username = username or "(unknown)"
            debug("Acquired data lock for user {}".format(username))
            info("Acquired data lock for user {}".format(username))
        else:
            debug("Failed to acquire lock for user {}, already locked by {}".format(username, self._lock_username))
            info("Failed to acquire lock for user {}, already locked by {}".format(username, self._lock_username))
        return res

    def unlock_data(self):
        self._data_lock.release()
        debug("Released data lock for user {}".format(self._lock_username))
        info("Released data lock for user {}".format(self._lock_username))
        self._lock_username = None


class JsonDatastore(BaseDatastore):
    def load_json(self, filename: str):
        with open(filename, "rt") as fp:
            self.data = self.dm.from_raw(json.load(fp))

    def save_json(self, filename: str):
        with open(filename, "w") as jfd:
            json.dump(self.data, jfd)

if __name__ == "__main__":
    colorlog.basicConfig(format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(message)s", level=logging.INFO,
                         stream=sys.stdout)

    nacm = NacmConfig()
    nacm.load_json("example-data.json")

    data = JsonDatastore("../data", "../data/yang-library-data.json")
    data.load_json("example-data.json")
    data.register_nacm(nacm)

    rpc = Rpc()
    rpc.username = "dominik"
    rpc.path = "/ietf-netconf-acm:nacm/groups"

    n = data.get_node_rpc(rpc)
    print(n.value)
