import json
from threading import Lock
from enum import Enum
from colorlog import error, warning as warn, info
from typing import List, Any, Dict, Callable, Optional

from yangson.datamodel import DataModel
from yangson.enumerations import ContentType, ValidationScope
from yangson.schema import (
    SchemaNode,
    NonexistentSchemaNode,
    ListNode,
    LeafListNode,
    SchemaError,
    SemanticError,
    InternalNode
)
from yangson.instance import (
    InstanceNode,
    NonexistentInstance,
    InstanceValueError,
    ArrayValue,
    ObjectValue,
    MemberName,
    EntryKeys,
    EntryIndex,
    InstanceRoute,
    ArrayEntry
)

from .helpers import PathFormat, ErrorHelpers, LogHelpers, DataHelpers
from .config import CONFIG
from .nacm import NacmConfig, Permission, Action
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES, CONF_DATA_HANDLES

epretty = ErrorHelpers.epretty
debug_data = LogHelpers.create_module_dbg_logger(__name__)


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


class InstanceAlreadyPresent(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class HandlerError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class NoHandlerError(HandlerError):
    pass


class NoHandlerForOpError(NoHandlerError):
    def __init__(self, op_name: str):
        self.op_name = op_name

    def __str__(self):
        return "Nonexistent handler for operation \"{}\"".format(self.op_name)


class NoHandlerForStateDataError(NoHandlerError):
    pass


class ConfHandlerResult(Enum):
    PASS = 0,
    OK = 1,
    ERROR = 2


class BaseDataListener:
    def __init__(self, ds: "BaseDatastore", sch_pth: str):
        self.ds = ds
        self.schema_path = sch_pth                          # type: str
        self.schema_node = ds.get_schema_node(sch_pth)      # type: SchemaNode

    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: "DataChange") -> ConfHandlerResult:
        raise NotImplementedError("Not implemented in base class")

    def __str__(self):
        return self.__class__.__name__ + ": listening at " + self.schema_path


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
        # Set new data root
        if hash(ds.get_data_root()) == hash(self.root_origin):
            info("Commiting new configuration (swapping roots)")
            # Set new root
            nr = self.get_root_head()
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

        try:
            # Validate syntax and semantics of new data
            nr.validate(ValidationScope.all, ContentType.config)
            new_data_valid = True
        except (SchemaError, SemanticError) as e:
            error("Data validation error:")
            error(epretty(e))
            new_data_valid = False

        if new_data_valid:
            # Set new data root
            ds.set_data_root(nr)

            # Run schema node handlers
            for cl in self.clists:
                for change in cl.journal:
                    ii = DataHelpers.parse_ii(change.rpc_info.path, change.rpc_info.path_format)
                    try:
                        ds.run_conf_edit_handler(ii, change)
                    except Exception as e:
                        ds.data_root_rollback(1, False)
                        raise e

            # Clear user changelists
            self.clists.clear()


class BaseDatastore:
    def __init__(self, dm: DataModel, name: str="", with_nacm: bool=False):
        self.name = name
        self.nacm = None    # type: NacmConfig
        self._data = None   # type: InstanceNode
        self._data_history = []     # type: List[InstanceNode]
        self._yang_lib_data = None  # type: InstanceNode
        self._dm = dm       # type: DataModel
        self._data_lock = Lock()
        self._lock_username = None  # type: str
        self._usr_journals = {}     # type: Dict[str, UsrChangeJournal]
        self.commit_begin_callback = None   # type: Callable[..., None]
        self.commit_end_callback = None     # type: Callable[..., None]

        if with_nacm:
            self.nacm = NacmConfig(self)

    # Returns the root node of data tree
    def get_data_root(self, previous_version: int=0) -> InstanceNode:
        if previous_version > 0:
            return self._data_history[-previous_version]
        else:
            return self._data

    def get_yl_data_root(self) -> InstanceNode:
        return self._yang_lib_data

    # Returns the root node of data tree
    def get_data_root_staging(self, username: str) -> InstanceNode:
        usr_journal = self._usr_journals.get(username)
        if usr_journal is not None:
            root = usr_journal.get_root_head()
            return root
        else:
            raise NoHandlerError("No active changelist for user \"{}\"".format(username))

    # Set a new Instance node as data root, store old root to archive
    def set_data_root(self, new_root: InstanceNode):
        self._data_history.append(self._data)
        self._data = new_root

    def data_root_rollback(self, history_steps: int, store_current: bool):
        if store_current:
            self._data_history.append(self._data)

        self._data = self._data_history[-history_steps]

    # Get schema node with particular schema address
    def get_schema_node(self, sch_pth: str) -> SchemaNode:
        sn = self._dm.get_schema_node(sch_pth)
        if sn is None:
            # raise NonexistentSchemaNode(sch_pth)
            debug_data("Cannot find schema node for " + sch_pth)
        return sn

    # Notify data observers about change in datastore
    def run_conf_edit_handler(self, ii: InstanceRoute, ch: DataChange) -> Optional[ConfHandlerResult]:
        h_res = None

        try:
            sch_pth_list = filter(lambda n: isinstance(n, MemberName), ii)
            sch_pth = DataHelpers.ii2str(sch_pth_list)
            sn = self.get_schema_node(sch_pth)

            while sn is not None:
                h = CONF_DATA_HANDLES.get_handler(str(id(sn)))
                if h is not None:
                    h_res = h.process(sn, ii, ch)
                    if h_res == ConfHandlerResult.OK:
                        # Edit successfully handled
                        break
                    elif h_res == ConfHandlerResult.ERROR:
                        # Error occured in handler
                        warn("Error occured in handler for sch_node \"{}\"".format(sch_pth))
                        break
                    else:
                        # Pass edit to superior handler
                        pass
                sn = sn.parent
        except NonexistentInstance:
            warn("Cannnot notify {}, parent container removed".format(ii))

        return h_res

    # Just get the node, do not evaluate NACM (needed for NACM)
    def get_node(self, root: InstanceNode, ii: InstanceRoute) -> InstanceNode:
        n = root.goto(ii)
        return n

    # Get data node, evaluate NACM if required
    def get_node_rpc(self, rpc: RpcInfo, yl_data=False) -> InstanceNode:
        ii = DataHelpers.parse_ii(rpc.path, rpc.path_format)
        if yl_data:
            root = self._yang_lib_data
        else:
            root = self._data

        n = root.goto(ii)
        sch_pth_list = filter(lambda n: isinstance(n, MemberName), ii)
        sch_pth = DataHelpers.ii2str(sch_pth_list)
        sn = self.get_schema_node(sch_pth)
        state_roots = sn.state_roots()

        if not yl_data and state_roots:
            self.commit_begin_callback()
            for state_node_pth in state_roots:
                sdh = STATE_DATA_HANDLES.get_handler(state_node_pth)
                if sdh is not None:
                    root_val = sdh.update_node(ii, root, True)
                    root = self._data.update(root_val, raw=True)
                else:
                    raise NoHandlerForStateDataError()
            self.commit_end_callback()

            n = root.goto(ii)

        try:
            with_defs = rpc.qs["with-defaults"][0]
        except (IndexError, KeyError):
            with_defs = None

        if with_defs == "report-all":
            n = n.add_defaults()

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prune nodes that should not be accessible to user
                n = nrpc.prune_data_tree(n, root, ii, Permission.NACM_ACCESS_READ)

        try:
            max_depth = int(rpc.qs["depth"][0])
        except (IndexError, KeyError):
            max_depth = None
        except ValueError:
            raise ValueError("Invalid value of query param \"depth\"")

        if max_depth is not None:
            def _tree_limit_depth(node: InstanceNode, depth: int) -> InstanceNode:
                if isinstance(node.value, ObjectValue):
                    if depth > max_depth:
                        node.value = ObjectValue({})
                    else:
                        for child_key in sorted(node.value.keys()):
                            m = node[child_key]
                            node = _tree_limit_depth(m, depth + 1).up()
                elif isinstance(node.value, ArrayValue):
                    if depth > max_depth:
                        node.value = ArrayValue([])
                    else:
                        for i in range(len(node.value)):
                            e = node[i]
                            node = _tree_limit_depth(e, depth + 1).up()

                return node
            n = _tree_limit_depth(n, 1)

        return n

    # Get staging data node, evaluate NACM if required
    def get_node_staging_rpc(self, rpc: RpcInfo) -> InstanceNode:
        ii = DataHelpers.parse_ii(rpc.path, rpc.path_format)

        root = self.get_data_root_staging(rpc.username)
        n = root.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prune nodes that should not be accessible to user
                n = nrpc.prune_data_tree(n, root, ii, Permission.NACM_ACCESS_READ)

        return n

    # Create new data node (Restconf draft compliant version)
    def create_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any) -> InstanceNode:
        ii = DataHelpers.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        insert = rpc.qs.get("insert", [None])[0]
        point = rpc.qs.get("point", [None])[0]

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_CREATE) == Action.DENY:
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
            existing_member = n[input_member_name]
        except NonexistentInstance:
            existing_member = None

        # Get target schema node
        n = root.goto(ii)

        sn = n.schema_node  # type: InternalNode
        sch_member_name = sn._iname2qname(input_member_name)
        member_sn = sn.get_data_child(*sch_member_name)

        if isinstance(member_sn, ListNode):
            # Append received node to list

            # Create list if necessary
            if existing_member is None:
                existing_member = n.put_member(input_member_name, ArrayValue([]))

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_list = member_sn.from_raw([input_member_value])
            new_value_item = new_value_list[0]    # type: ObjectValue

            list_node_key = member_sn.keys[0][0]
            if new_value_item[list_node_key] in map(lambda x: x[list_node_key], existing_member.value):
                raise InstanceAlreadyPresent("Duplicate key")

            if insert == "first":
                # Optimization
                if len(existing_member) > 0:
                    list_entry_first = existing_member[0]   # type: ArrayEntry
                    new_member = list_entry_first.insert_after(new_value_item).up()
                else:
                    new_member = existing_member.update(new_value_list)
            elif (insert == "last") or insert is None:
                # Optimization
                if len(existing_member) > 0:
                    list_entry_last = existing_member[-1]   # type: ArrayEntry
                    new_member = list_entry_last.insert_after(new_value_item).up()
                else:
                    new_member = existing_member.update(new_value_list)
            elif insert == "before":
                entry_sel = EntryKeys({list_node_key: point})
                list_entry = entry_sel.goto_step(existing_member)   # type: ArrayEntry
                new_member = list_entry.insert_before(new_value_item).up()
            elif insert == "after":
                entry_sel = EntryKeys({list_node_key: point})
                list_entry = entry_sel.goto_step(existing_member)   # type: ArrayEntry
                new_member = list_entry.insert_after(new_value_item).up()
            else:
                raise ValueError("Invalid 'insert' value")
        elif isinstance(member_sn, LeafListNode):
            # Append received node to leaf list

            # Create leaf list if necessary
            if existing_member is None:
                existing_member = n.put_member(input_member_name, ArrayValue([]))

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_item = member_sn.from_raw([input_member_value])[0]

            if insert == "first":
                new_member = existing_member.update(ArrayValue([new_value_item] + existing_member.value))
            elif (insert == "last") or insert is None:
                new_member = existing_member.update(ArrayValue(existing_member.value + [new_value_item]))
            else:
                raise ValueError("Invalid 'insert' value")
        else:
            if existing_member is None:
                # Create new data node

                # Convert input data from List/Dict to ArrayValue/ObjectValue
                new_value_item = member_sn.from_raw(input_member_value)

                # Create new node (object member)
                new_member = n.put_member(input_member_name, new_value_item)
            else:
                # Data node already exists
                raise InstanceAlreadyPresent("Member \"{}\" already present in \"{}\"".format(input_member_name, ii))

        return new_member.top()

    # PUT data node
    def update_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any) -> InstanceNode:
        ii = DataHelpers.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_UPDATE) == Action.DENY:
                raise NacmForbiddenError()

        new_n = n.update(value, raw=True)

        return new_n.top()

    # Delete data node
    def delete_node_rpc(self, root: InstanceNode, rpc: RpcInfo) -> InstanceNode:
        ii = DataHelpers.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)
        n_parent = n.up()
        last_isel = ii[-1]

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_DELETE) == Action.DENY:
                raise NacmForbiddenError()

        new_n = n_parent
        if isinstance(n_parent.value, ArrayValue):
            if isinstance(last_isel, EntryIndex):
                new_n = n_parent.delete_item(last_isel.key)
            elif isinstance(last_isel, EntryKeys):
                new_n = n_parent.delete_item(n.index)
        elif isinstance(n_parent.value, ObjectValue):
            if isinstance(last_isel, MemberName):
                new_n = n_parent.delete_item(last_isel.key)
        else:
            raise InstanceValueError(n, "Invalid target node type")

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

            try:
                cl_name = rpc.op_input_args["name"]
            except (TypeError, KeyError):
                raise ValueError("This operation expects \"name\" input parameter")

            self._usr_journals[rpc.username].cl_new(cl_name)
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

                try:
                    self.lock_data(rpc.username)
                    old_root = self._data
                    usr_journal.commit(self)
                    if CONFIG["GLOBAL"]["PERSISTENT_CHANGES"] is True:
                        self.save()
                finally:
                    self.unlock_data()

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
                raise NoHandlerForOpError(rpc.op_name)

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
            debug_data("Acquired lock in datastore \"{}\" for user \"{}\"".format(self.name, username))
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
        debug_data("Released lock in datastore \"{}\" for user \"{}\"".format(self.name, self._lock_username))
        self._lock_username = None

    # Load data from persistent storage
    def load(self):
        raise NotImplementedError("Not implemented in base class")

    # Save data to persistent storage
    def save(self):
        raise NotImplementedError("Not implemented in base class")


class JsonDatastore(BaseDatastore):
    def __init__(self, dm: DataModel, json_file: str, name: str = "", with_nacm: bool=False):
        super().__init__(dm, name, with_nacm)
        self.json_file = json_file

    def load(self):
        self._data = None
        with open(self.json_file, "rt") as fp:
            self._data = self._dm.from_raw(json.load(fp))

        if self.nacm is not None:
            self.nacm.update()

    def load_yl_data(self, filename: str):
        self._yang_lib_data = None
        with open(filename, "rt") as fp:
            self._yang_lib_data = self._dm.from_raw(json.load(fp))

    def save(self):
        with open(self.json_file, "w") as jfd:
            json.dump(self._data.raw_value(), jfd, indent=4)


def test():
    error("Tests moved to tests/tests_jetconf.py")
