import json
from threading import Lock
from enum import Enum
from colorlog import error, warning as warn, info, debug
from typing import List, Any, Dict, TypeVar, Tuple, Set
from pydispatch import dispatcher

from yangson.schema import SchemaRoute, SchemaNode, NonexistentSchemaNode, ListNode, LeafListNode
from yangson.context import Context
from yangson.datamodel import InstanceIdentifier, DataModel
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
    def __init__(self, ds: "BaseDatastore"):
        self._ds = ds
        self.schema_paths = []

    def add_schema_node(self, sch_pth: str):
        sn = self._ds.get_schema_node(sch_pth)
        self.schema_paths.append(sch_pth)
        dispatcher.connect(self.process, str(id(sn)))

    def process(self, sn: SchemaNode, ii: InstanceIdentifier):
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
    def __init__(self, changelist_name: str):
        self.changelist_name = changelist_name
        self.journal = []   # type: List[DataChange]

    def add(self, change: DataChange):
        self.journal.append(change)


class BaseDatastore:
    def __init__(self, dm: DataModel, name: str=""):
        self.name = name
        self.nacm = None    # type: NacmConfig
        self._data = None   # type: InstanceNode
        self._dm = dm       # type: DataModel
        self._data_lock = Lock()
        self._lock_username = None  # type: str
        self._usr_changelist = {}   # type: Dict[str, List[ChangeList]]

    # Register NACM module to datastore
    def register_nacm(self, nacm_config: "NacmConfig"):
        self.nacm = nacm_config

    # Returns the root node of data tree
    def get_data_root(self) -> InstanceNode:
        return self._data

    # Get schema node with particular schema address
    def get_schema_node(self, sch_pth: str) -> SchemaNode:
        sn = self._dm.get_schema_node(sch_pth)
        if sn is None:
            raise NonexistentSchemaNode(sch_pth)
        return sn

    # Get schema node for particular data node
    def get_schema_node_ii(self, ii: InstanceIdentifier) -> SchemaNode:
        sn = Context.schema.get_data_descendant(ii)
        return sn

    # Parse Instance Identifier from string
    def parse_ii(self, path: str, path_format: PathFormat) -> InstanceIdentifier:
        if path_format == PathFormat.URL:
            ii = self._dm.parse_resource_id(path)
        else:
            ii = self._dm.parse_instance_id(path)

        return ii

    # Notify data observers about change in datastore
    def notify_edit(self, ii: InstanceIdentifier):
        sn = self.get_schema_node_ii(ii)
        while sn is not None:
            dispatcher.send(str(id(sn)), **{'sn': sn, 'ii': ii})
            sn = sn.parent

    # Just get the node, do not evaluate NACM (for testing purposes)
    def get_node(self, ii: InstanceIdentifier) -> InstanceNode:
        n = self._data.goto(ii)
        return n

    # Just get the node, do not evaluate NACM (for testing purposes)
    def get_node_path(self, path: str, path_format: PathFormat) -> InstanceNode:
        ii = self.parse_ii(path, path_format)
        n = self._data.goto(ii)
        return n

    # Get data node, evaluate NACM if required
    def get_node_rpc(self, rpc: RpcInfo) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        root = self._data

        sn = self.get_schema_node_ii(ii)
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
            if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prun subtree data
                n = nrpc.check_data_read_path(ii)

        return n

    # Create new data node (Restconf draft compliant version)
    def create_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any, insert=None, point=None) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)
        new_n = n

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_CREATE) == Action.DENY:
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
        member_sn = self.get_schema_node_ii(ii + [MemberName(input_member_name)])

        if isinstance(member_sn, ListNode):
            # Append received node to list

            # Create list if necessary
            if existing_member is None:
                existing_member = n.new_member(input_member_name, ArrayValue([]))

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_data = member_sn.from_raw([input_member_value])[0]

            list_node_key = member_sn.keys[0][0]
            if new_value_data[list_node_key] in map(lambda x: x[list_node_key], existing_member.value):
                raise InstanceAlreadyPresent("Duplicate key")

            if insert == "first":
                new_n = existing_member.update(ArrayValue([new_value_data] + existing_member.value))
            elif (insert == "last") or insert is None:
                new_n = existing_member.update(ArrayValue(existing_member.value + [new_value_data]))
            elif insert == "before":
                entry_sel = EntryKeys({list_node_key: point})
                list_entry = entry_sel.goto_step(existing_member)
                new_n = list_entry.insert_before(new_value_data).up()
            elif insert == "after":
                entry_sel = EntryKeys({list_node_key: point})
                list_entry = entry_sel.goto_step(existing_member)
                new_n = list_entry.insert_after(new_value_data).up()
        elif isinstance(member_sn, LeafListNode):
            # Append received node to leaf list

            # Create leaf list if necessary
            if existing_member is None:
                existing_member = n.new_member(input_member_name, ArrayValue([]))

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_data = member_sn.from_raw([input_member_value])[0]

            if insert == "first":
                new_n = existing_member.update(ArrayValue([new_value_data] + existing_member.value))
            elif (insert == "last") or insert is None:
                new_n = existing_member.update(ArrayValue(existing_member.value + [new_value_data]))
        else:
            if existing_member is None:
                # Create new data node

                # Convert input data from List/Dict to ArrayValue/ObjectValue
                new_value_data = member_sn.from_raw(input_member_value)

                # Create new node (object member)
                new_n = n.new_member(input_member_name, new_value_data)
            else:
                # Data node already exists
                raise InstanceAlreadyPresent("Member \"{}\" already present in \"{}\"".format(input_member_name, ii))

        self.notify_edit(ii)
        return new_n.top()

    # Update already existing data node
    def update_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        if self.nacm:
            nrpc = self.nacm.get_user_nacm(rpc.username)
            if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_UPDATE) == Action.DENY:
                raise NacmForbiddenError()

        sn = self.get_schema_node_ii(ii)
        new_value = sn.from_raw(value)
        new_n = n.update(new_value)

        self.notify_edit(ii)
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
            if nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_DELETE) == Action.DENY:
                raise NacmForbiddenError()

        if isinstance(n_parent.value, ArrayValue):
            if isinstance(last_isel, EntryIndex):
                new_n = n_parent.remove_entry(last_isel.index)
            elif isinstance(last_isel, EntryKeys):
                new_n = n_parent.remove_entry(n.crumb.pointer_fragment())
        elif isinstance(n_parent.value, ObjectValue):
            if isinstance(last_isel, MemberName):
                new_n = n_parent.remove_member(last_isel.name)
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
            chl = ChangeList(rpc.op_input_args["name"])
            if self._usr_changelist.get(rpc.username) is None:
                self._usr_changelist[rpc.username] = []
            self._usr_changelist[rpc.username].append(chl)
            ret_data = {"status": "OK"}
        elif rpc.op_name == "conf-list":
            chls = self._usr_changelist.get(rpc.username)
            chl_json = {}
            for chl in chls:
                changes = []
                for ch in chl.journal:
                    changes.append(
                        [ch.change_type.name, ch.rpc_info.path]
                    )

                chl_json[chl.changelist_name] = changes
            ret_data = \
                {
                    "status": "OK",
                    "changelists": chl_json
                }
        elif rpc.op_name == "conf-drop":
            chls = self._usr_changelist.get(rpc.username)
            if chls is not None:
                chls.pop()
                if len(chls) == 0:
                    del self._usr_changelist[rpc.username]

            ret_data = {"status": "OK"}
        elif rpc.op_name == "conf-commit":
            pass
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

    def add_to_journal_rpc(self, type: ChangeType, rpc: RpcInfo, value: Any):
        usr_chss = self._usr_changelist.get(rpc.username)
        if usr_chss is not None:
            usr_chs = usr_chss[-1]
            usr_chs.add(DataChange(type, rpc, value))
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
    datamodel = DataHelpers.load_data_model("./data", "./data/yang-library-data.json")
    data = JsonDatastore(datamodel)
    data.load("jetconf/example-data.json")

    rpc = RpcInfo()
    rpc.username = "dominik"
    rpc.path = "/dns-server:dns-server/zones/zone[domain='example.com']/query-module"
    rpc.path_format = PathFormat.XPATH

    info("Testing read of " + rpc.path)
    n = data.get_node_rpc(rpc)
    info("Result =")
    print(n.value)
    expected_value = \
        [
            {'name': 'test1', 'type': 'knot-dns:synth-record'},
            {'name': 'test2', 'type': 'knot-dns:synth-record'}
        ]

    if json.loads(json.dumps(n.value)) == expected_value:
        info("OK")
    else:
        warn("FAILED")

    rpc.path = "/dns-server:dns-server/zones"
    rpc.path_format = PathFormat.URL
    info("Testing creation of new list item (zone myzone.com) in " + rpc.path)

    new_root = data.create_node_rpc(data.get_data_root(), rpc, {"zone": {"domain": "myzone.com"}})
    new_node_ii = data.parse_ii("/dns-server:dns-server/zones/zone", PathFormat.URL)
    new_node = new_root.goto(new_node_ii)
    info("Result =")
    print(json.dumps(new_node.value, indent=4))

    if "myzone.com" in map(lambda x: x.get("domain"), new_node.value):
        info("OK")
    else:
        warn("FAILED")

    rpc.path = "/dns-server:dns-server/zones/zone=myzone.com"
    rpc.path_format = PathFormat.URL
    info("Testing creation of new leaf-list inside object " + rpc.path)

    new_root2 = data.create_node_rpc(new_root, rpc, {"access-control-list": "acl-notify-pokus"})
    new_node_ii = data.parse_ii("/dns-server:dns-server/zones/zone=myzone.com", PathFormat.URL)
    new_node2 = new_root2.goto(new_node_ii)
    info("Result =")
    print(json.dumps(new_node2.value, indent=4))

    if "acl-notify-pokus" in new_node2.member("access-control-list").value:
        info("OK")
    else:
        warn("FAILED")


from .nacm import NacmConfig, Permission, Action
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES
