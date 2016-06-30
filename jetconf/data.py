import json
from threading import Lock
from enum import Enum
from colorlog import error, warning as warn, info, debug
from typing import List, Any, Dict, TypeVar, Tuple, Set, Callable
from pydispatch import dispatcher

from yangson.schema import SchemaRoute, SchemaNode, NonexistentSchemaNode, ListNode, LeafListNode
from yangson.datamodel import DataModel, InstancePath
from yangson.instance import \
    InstanceNode, \
    NonexistentInstance, \
    InstanceTypeError, \
    ArrayValue, \
    ObjectValue, \
    MemberName, \
    EntryKeys, \
    EntryIndex

from .helpers import DataHelpers


class PathFormat(Enum):
    URL = 0
    XPATH = 1


class ChangeType(Enum):
    CREATE = 0,
    REPLACE = 1,
    DELETE = 2


class NacmForbiddenError(Exception):
    def __init__(self, msg="Access to data node rejected by NACM", rule=None):
        self.msg = msg
        self.rulename = rule

    def __str__(self):
        return self.msg


class DataLockError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class NoHandlerError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class InstanceAlreadyPresent(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class NoHandlerForOpError(NoHandlerError):
    pass


class NoHandlerForStateDataError(NoHandlerError):
    pass


class BaseDataListener:
    def __init__(self, ds: "BaseDatastore", sch_pth: str):
        self._ds = ds
        self.schema_path = sch_pth                          # type: str
        self.schema_node = ds.get_schema_node(sch_pth)      # type: SchemaNode
        dispatcher.connect(self.process, str(id(self.schema_node)))

    def process(self, sn: SchemaNode, ii: InstancePath, ch: "DataChange"):
        raise NotImplementedError("Not implemented in base class")

    def __str__(self):
        return self.__class__.__name__ + ": listening at " + str(self.schema_paths)


class RpcInfo:
    def __init__(self):
        self.username = None    # type: str
        self.path = None        # type: str
        self.qs = None          # type: Dict[str, List[str]]
        self.path_format = PathFormat.URL   # type: PathFormat
        self.skip_nacm_check = False        # type: bool
        self.op_name = None                 # type: str
        self.op_input_args = None           # type: ObjectValue


class DataChange:
    def __init__(self, change_type: ChangeType, rpc_info: RpcInfo, data: Any):
        self.change_type = change_type
        self.rpc_info = rpc_info
        self.data = data


class ChangeList:
    def __init__(self, root_origin_cl: InstanceNode, changelist_name: str):
        self.root_list = [root_origin_cl]
        self.changelist_name = changelist_name
        self.journal = []   # type: List[DataChange]

    def add(self, change: DataChange, root_after_change: InstanceNode):
        self.journal.append(change)
        self.root_list.append(root_after_change)


class UsrChangeJournal:
    def __init__(self, root_origin: InstanceNode):
        self.root_origin = root_origin
        self.clists = []    # type: List[ChangeList]

    def cl_new(self, cl_name: str):
        self.clists.append(ChangeList(self.get_root_head(), cl_name))

    def cl_drop(self) -> bool:
        try:
            self.clists.pop()
            return True
        except IndexError:
            return False

    def get_root_head(self) -> InstanceNode:
        if len(self.clists) > 0:
            return self.clists[-1].root_list[-1]
        else:
            return self.root_origin

    def list(self) -> str:
        chl_json = {}
        for chl in self.clists:
            changes = []
            for ch in chl.journal:
                changes.append(
                    [ch.change_type.name, ch.rpc_info.path]
                )

            chl_json[chl.changelist_name] = changes

        return chl_json

    def commit(self, ds: "BaseDatastore"):
        # ds.lock_data()
        try:
            # Set new data root
            if hash(ds.get_data_root()) == hash(self.root_origin):
                info("Commiting new configuration (swapping roots)")
                # Set new root
                ds.set_data_root(self.get_root_head())
            else:
                info("Commiting new configuration (re-applying changes)")
                nr = ds.get_data_root()
                for cl in self.clists:
                    for change in cl.journal:
                        if change.change_type == ChangeType.CREATE:
                            nr = ds.create_node_rpc(nr, change.rpc_info, change.data)
                        elif change.change_type == ChangeType.REPLACE:
                            nr = ds.update_node_rpc(nr, change.rpc_info, change.data)
                        elif change.change_type == ChangeType.DELETE:
                            nr = ds.delete_node_rpc(nr, change.rpc_info)
                ds.set_data_root(nr)

            # Notify schema node observers
            for cl in self.clists:
                for change in cl.journal:
                    ii = ds.parse_ii(change.rpc_info.path, change.rpc_info.path_format)
                    ds.notify_edit(ii, change)
                    # if change.change_type != ChangeType.DELETE:
                    #     ds.notify_edit(ii)
                    # else:
                    #     ds.notify_edit(ii[0:-1])

            # Clear user changelists
            self.clists.clear()
        finally:
            # ds.unlock_data()
            pass


class BaseDatastore:
    def __init__(self, dm: DataModel, name: str=""):
        self.name = name
        self.nacm = None    # type: NacmConfig
        self._data = None   # type: InstanceNode
        self._dm = dm       # type: DataModel
        self._data_lock = Lock()
        self._lock_username = None  # type: str
        self._usr_journals = {}   # type: Dict[str, UsrChangeJournal]
        self.commit_begin_callback = None   # type: Callable
        self.commit_end_callback = None     # type: Callable

    # Register NACM module to datastore
    def register_nacm(self, nacm_config: "NacmConfig"):
        self.nacm = nacm_config

    # Returns the root node of data tree
    def get_data_root(self) -> InstanceNode:
        return self._data

    # Returns the root node of data tree
    def get_data_root_staging(self, username: str) -> InstanceNode:
        usr_journal = self._usr_journals.get(username)
        if usr_journal is not None:
            root = usr_journal.get_root_head()
            return root
        else:
            raise NoHandlerError("No active changelist for user \"{}\"".format(username))

    # Set a new Instance node as data root
    def set_data_root(self, new_root: InstanceNode):
        self._data = new_root

    # Get schema node with particular schema address
    def get_schema_node(self, sch_pth: str) -> SchemaNode:
        sn = self._dm.get_schema_node(sch_pth)
        if sn is None:
            raise NonexistentSchemaNode(sch_pth)
        return sn

    # Parse Instance Identifier from string
    def parse_ii(self, path: str, path_format: PathFormat) -> InstancePath:
        if path_format == PathFormat.URL:
            ii = self._dm.parse_resource_id(path)
        else:
            ii = self._dm.parse_instance_id(path)

        return ii

    # Notify data observers about change in datastore
    def notify_edit(self, ii: InstancePath, ch: DataChange):
        try:
            # n = self._data.goto(ii)
            # sn = n.schema_node
            sch_pth = str(InstancePath(filter(lambda n: isinstance(n, MemberName), ii)))
            sn = self.get_schema_node(sch_pth)

            while sn is not None:
                dispatcher.send(str(id(sn)), **{'sn': sn, 'ii': ii, 'ch': ch})
                sn = sn.parent
        except NonexistentInstance:
            warn("Cannnot notify {}, parent container removed".format(ii))

    # Just get the node, do not evaluate NACM (needed for NACM)
    def get_node(self, root: InstanceNode, ii: InstancePath) -> InstanceNode:
        n = root.goto(ii)
        return n

    # Get data node, evaluate NACM if required
    def get_node_rpc(self, rpc: RpcInfo) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        root = self._data
        n = root.goto(ii)
        sn = n.schema_node

        for state_node_pth in sn.state_roots():
            sn_pth_str = "".join(["/" + pth_seg for pth_seg in state_node_pth])
            # print(sn_pth_str)
            sdh = STATE_DATA_HANDLES.get_handler(sn_pth_str)
            if sdh is not None:
                root = sdh.update_node(ii, root).top()
                self._data = root
            else:
                raise NoHandlerForStateDataError()

        self._data = root
        n = self._data.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(self._data, ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prun subtree data
                n = nrpc.check_data_read_path(self._data, ii)

        return n

    # Get staging data node, evaluate NACM if required
    def get_node_staging_rpc(self, rpc: RpcInfo) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)

        root = self.get_data_root_staging(rpc.username)
        n = root.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(root, ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prun subtree data
                n = nrpc.check_data_read_path(root, ii)

        return n

    # Create new data node (Restconf draft compliant version)
    def create_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any, insert=None, point=None) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(root, ii, Permission.NACM_ACCESS_CREATE) == Action.DENY:
                raise NacmForbiddenError()

        # Get target member name
        input_member_name = tuple(value.keys())
        if len(input_member_name) != 1:
            raise ValueError("Received json object must contain exactly one member")
        else:
            input_member_name = input_member_name[0]

        input_member_value = value[input_member_name]

        # Check if target member already exists
        try:
            existing_member = n.member(input_member_name)
        except NonexistentInstance:
            existing_member = None

        # Get target schema node
        n = root.goto(ii)

        sn = n.schema_node
        sch_member_name = sn.iname2qname(input_member_name)
        member_sn = sn.get_data_child(*sch_member_name)

        if isinstance(member_sn, ListNode):
            # Append received node to list

            # Create list if necessary
            if existing_member is None:
                new_n = n.put_member(input_member_name, ArrayValue([]))
                existing_member = new_n.member(input_member_name)

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_data = member_sn.from_raw([input_member_value])[0]

            list_node_key = member_sn.keys[0][0]
            if new_value_data[list_node_key] in map(lambda x: x[list_node_key], existing_member.value):
                raise InstanceAlreadyPresent("Duplicate key")

            if insert == "first":
                new_member = existing_member.update(ArrayValue([new_value_data] + existing_member.value))
            elif (insert == "last") or insert is None:
                new_member = existing_member.update(ArrayValue(existing_member.value + [new_value_data]))
            elif insert == "before":
                entry_sel = EntryKeys({list_node_key: point})
                list_entry = entry_sel.goto_step(existing_member)
                new_member = list_entry.insert_before(new_value_data).up()
            elif insert == "after":
                entry_sel = EntryKeys({list_node_key: point})
                list_entry = entry_sel.goto_step(existing_member)
                new_member = list_entry.insert_after(new_value_data).up()
            else:
                raise ValueError("Invalid 'insert' value")
        elif isinstance(member_sn, LeafListNode):
            # Append received node to leaf list

            # Create leaf list if necessary
            if existing_member is None:
                new_n = n.put_member(input_member_name, ArrayValue([]))
                existing_member = new_n.member(input_member_name)

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_data = member_sn.from_raw([input_member_value])[0]

            if insert == "first":
                new_member = existing_member.update(ArrayValue([new_value_data] + existing_member.value))
            elif (insert == "last") or insert is None:
                new_member = existing_member.update(ArrayValue(existing_member.value + [new_value_data]))
            else:
                raise ValueError("Invalid 'insert' value")
        else:
            if existing_member is None:
                # Create new data node

                # Convert input data from List/Dict to ArrayValue/ObjectValue
                new_value_data = member_sn.from_raw(input_member_value)

                # Create new node (object member)
                new_member = n.put_member(input_member_name, new_value_data)
            else:
                # Data node already exists
                raise InstanceAlreadyPresent("Member \"{}\" already present in \"{}\"".format(input_member_name, ii))

        return new_member.top()

    # PUT data node
    def update_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(root, ii, Permission.NACM_ACCESS_UPDATE) == Action.DENY:
                raise NacmForbiddenError()

        new_n = n.update_from_raw(value)

        return new_n.top()

    # Delete data node
    def delete_node_rpc(self, root: InstanceNode, rpc: RpcInfo) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)
        n_parent = n.up()
        new_n = n_parent
        last_isel = ii[-1]

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(root, ii, Permission.NACM_ACCESS_DELETE) == Action.DENY:
                raise NacmForbiddenError()

        if isinstance(n_parent.value, ArrayValue):
            if isinstance(last_isel, EntryIndex):
                new_n = n_parent.delete_entry(last_isel.index)
            elif isinstance(last_isel, EntryKeys):
                new_n = n_parent.delete_entry(n.index)
        elif isinstance(n_parent.value, ObjectValue):
            if isinstance(last_isel, MemberName):
                new_n = n_parent.delete_member(last_isel.name)
        else:
            raise InstanceTypeError(n, "Invalid target node type")

        return new_n.top()

    # Invoke an operation
    def invoke_op_rpc(self, rpc: RpcInfo) -> ObjectValue:
        if self.nacm and (not rpc.skip_nacm_check):
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_rpc_name(rpc.op_name) == Action.DENY:
                raise NacmForbiddenError("Op \"{}\" invocation denied for user \"{}\"".format(rpc.op_name, rpc.username))

        ret_data = {}

        if rpc.op_name == "conf-start":
            if self._usr_journals.get(rpc.username) is None:
                self._usr_journals[rpc.username] = UsrChangeJournal(self._data)

            self._usr_journals[rpc.username].cl_new(rpc.op_input_args["name"])
            ret_data = {"status": "OK"}
        elif rpc.op_name == "conf-list":
            usr_journal = self._usr_journals.get(rpc.username)
            if usr_journal is not None:
                chl_json = usr_journal.list()
            else:
                chl_json = str(None)

            ret_data = \
                {
                    "status": "OK",
                    "changelists": chl_json
                }
        elif rpc.op_name == "conf-drop":
            usr_journal = self._usr_journals.get(rpc.username)
            if usr_journal is not None:
                if not usr_journal.cl_drop():
                    del self._usr_journals[rpc.username]

            ret_data = {"status": "OK"}
        elif rpc.op_name == "conf-commit":
            usr_journal = self._usr_journals.get(rpc.username)
            if usr_journal is not None:
                if self.commit_begin_callback is not None:
                    self.commit_begin_callback()
                usr_journal.commit(self)
                if self.commit_end_callback is not None:
                    self.commit_end_callback()
                del self._usr_journals[rpc.username]
            else:
                warn("Nothing to commit")

            ret_data = \
                {
                    "status": "OK",
                    "conf-changed": True
                }
        else:
            op_handler = OP_HANDLERS.get_handler(rpc.op_name)
            if op_handler is None:
                raise NoHandlerForOpError()

            # Print operation input schema
            # sn = self.get_schema_node(rpc.path)
            # sn_input = sn.get_child("input")
            # if sn_input is not None:
            #     print("RPC input schema:")
            #     print(sn_input._ascii_tree(""))

            ret_data = op_handler(rpc.op_input_args)

        return ret_data

    def add_to_journal_rpc(self, ch_type: ChangeType, rpc: RpcInfo, value: Any, new_root: InstanceNode):
        usr_journal = self._usr_journals.get(rpc.username)
        if usr_journal is not None:
            usr_chs = usr_journal.clists[-1]
            usr_chs.add(DataChange(ch_type, rpc, value), new_root)
        else:
            raise NoHandlerError("No active changelist for user \"{}\"".format(rpc.username))

    # Locks datastore data
    def lock_data(self, username: str = None, blocking: bool=True):
        ret = self._data_lock.acquire(blocking=blocking, timeout=1)
        if ret:
            self._lock_username = username or "(unknown)"
            debug("Acquired lock in datastore \"{}\" for user \"{}\"".format(self.name, username))
        else:
            raise DataLockError(
                "Failed to acquire lock in datastore \"{}\" for user \"{}\", already locked by \"{}\"".format(
                    self.name,
                    username,
                    self._lock_username
                )
            )

    # Unlock datastore data
    def unlock_data(self):
        self._data_lock.release()
        debug("Released lock in datastore \"{}\" for user \"{}\"".format(self.name, self._lock_username))
        self._lock_username = None

    # Load data from persistent storage
    def load(self, filename: str):
        raise NotImplementedError("Not implemented in base class")

    # Save data to persistent storage
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
    error("Tests moved to tests/tests_jetconf.py")


from .nacm import NacmConfig, Permission, Action
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES
