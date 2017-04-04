import json

from threading import Lock
from enum import Enum
from colorlog import error, warning as warn, info
from typing import List, Any, Dict, Callable, Optional
from datetime import datetime

from yangson.datamodel import DataModel
from yangson.enumerations import ContentType, ValidationScope
from yangson.schemanode import (
    SchemaNode,
    ListNode,
    LeafListNode,
    SchemaError,
    SemanticError,
    InternalNode,
    ContainerNode
)
from yangson.instvalue import ArrayValue, ObjectValue
from yangson.instance import (
    InstanceNode,
    NonexistentInstance,
    InstanceValueError,
    MemberName,
    EntryKeys,
    EntryIndex,
    InstanceRoute,
    ArrayEntry,
    RootNode,
    ObjectMember
)

from .helpers import PathFormat, ErrorHelpers, LogHelpers, DataHelpers, JsonNodeT
from .config import CONFIG, CONFIG_NACM, CONFIG_HTTP
from .nacm import NacmConfig, Permission, Action, NacmForbiddenError
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES, CONF_DATA_HANDLES, ConfDataObjectHandler, ConfDataListHandler
from .usr_state_data_handlers import ContainerNodeHandlerBase, ListNodeHandlerBase
from .errors import JetconfError

epretty = ErrorHelpers.epretty
debug_data = LogHelpers.create_module_dbg_logger(__name__)


class ChangeType(Enum):
    CREATE = 0,
    REPLACE = 1,
    DELETE = 2


class DataLockError(JetconfError):
    pass


class NoStagingDataException(JetconfError):
    pass


class InstanceAlreadyPresent(JetconfError):
    pass


class HandlerError(JetconfError):
    pass


class NoHandlerError(HandlerError):
    pass


class ConfHandlerFailedError(HandlerError):
    pass

class OpHandlerFailedError(HandlerError):
    pass

class NoHandlerForOpError(NoHandlerError):
    def __init__(self, op_name: str):
        self.op_name = op_name

    def __str__(self):
        return "Nonexistent handler for operation \"{}\"".format(self.op_name)


class NoHandlerForStateDataError(NoHandlerError):
    pass


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
    def __init__(self, root_origin: InstanceNode, transaction_opts: Optional[JsonNodeT]):
        self.root_origin = root_origin
        self.transaction_opts = transaction_opts
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
            if CONFIG["GLOBAL"]["VALIDATE_TRANSACTIONS"] is True:
                nr.validate(ValidationScope.all, ContentType.config)
        except (SchemaError, SemanticError) as e:
            error("Data validation error:")
            error(epretty(e))
            raise e

        # Set new data root
        ds.set_data_root(nr)

        # Call commit begin hook
        begin_hook_failed = False
        try:
            ds.commit_begin_callback(self.transaction_opts)
        except Exception as e:
            error("Exception occured in commit_begin handler: {}".format(epretty(e)))
            begin_hook_failed = True

        # Run schema node handlers
        conf_handler_failed = False
        if not begin_hook_failed:
            try:
                for cl in self.clists:
                    for change in cl.journal:
                        ii = ds.parse_ii(change.rpc_info.path, change.rpc_info.path_format)
                        ds.run_conf_edit_handler(ii, change)
            except IndexError as e:
                error("Exception occured in edit handler: {}".format(epretty(e)))
                conf_handler_failed = True

        # Call commit end hook
        end_hook_failed = False
        end_hook_abort_failed = False
        if not (begin_hook_failed or conf_handler_failed):
            try:
                ds.commit_end_callback(self.transaction_opts, failed=False)
            except Exception as e:
                error("Exception occured in commit_end handler: {}".format(epretty(e)))
                end_hook_failed = True

        if begin_hook_failed or conf_handler_failed or end_hook_failed:
            try:
                # Call commit_end callback again with "failed" argument set to True
                ds.commit_end_callback(self.transaction_opts, failed=True)
            except Exception as e:
                error("Exception occured in commit_end handler (abort): {}".format(epretty(e)))
                end_hook_abort_failed = True

        # Clear user changelists
        self.clists.clear()

        # Return to previous version of data and raise an exception if something went wrong
        if begin_hook_failed or conf_handler_failed or end_hook_failed or end_hook_abort_failed:
            ds.data_root_rollback(history_steps=1, store_current=False)
            raise ConfHandlerFailedError("(see logged)")


class BaseDatastore:
    def __init__(self, dm: DataModel, name: str="", with_nacm: bool=False):
        def _blankfn(*args, **kwargs):
            pass

        self.name = name
        self.nacm = None    # type: NacmConfig
        self._data = None   # type: InstanceNode
        self._data_history = []     # type: List[InstanceNode]
        self._yang_lib_data = None  # type: InstanceNode
        self._dm = dm       # type: DataModel
        self._data_lock = Lock()
        self._lock_username = None  # type: str
        self._usr_journals = {}     # type: Dict[str, UsrChangeJournal]
        self.commit_begin_callback = _blankfn   # type: Callable[..., bool]
        self.commit_end_callback = _blankfn     # type: Callable[..., bool]

        if with_nacm:
            self.nacm = NacmConfig(self, self._dm)

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
            raise NoStagingDataException("No active changelist for user \"{}\"".format(username))

    # Set a new Instance node as data root, store old root to archive
    def set_data_root(self, new_root: InstanceNode):
        self._data_history.append(self._data)
        self._data = new_root

    def data_root_rollback(self, history_steps: int, store_current: bool):
        if store_current:
            self._data_history.append(self._data)

        self._data = self._data_history[-history_steps]

    def parse_ii(self, path: str, path_format: PathFormat) -> InstanceRoute:
        if path_format == PathFormat.URL:
            ii = self._dm.parse_resource_id(path)
        else:
            ii = self._dm.parse_instance_id(path)

        return ii

    # Get schema node with particular schema address
    def get_schema_node(self, sch_pth: str) -> SchemaNode:
        sn = self._dm.get_data_node(sch_pth)
        if sn is None:
            # raise NonexistentSchemaNode(sch_pth)
            debug_data("Cannot find schema node for " + sch_pth)
        return sn

    # Notify data observers about change in datastore
    def run_conf_edit_handler(self, ii: InstanceRoute, ch: DataChange):
        try:
            sch_pth_list = list(filter(lambda n: isinstance(n, MemberName), ii))

            if ch.change_type == ChangeType.CREATE:
                # Get target member name
                input_member_name_fq = tuple(ch.data.keys())[0]
                input_member_name_ns, input_member_name = input_member_name_fq.split(":", maxsplit=1)
                # Append it to ii
                sch_pth_list.append(MemberName(input_member_name, None))

            sch_pth = DataHelpers.ii2str(sch_pth_list)
            print(sch_pth)
            sn = self.get_schema_node(sch_pth)

            if sn is None:
                return

            h = CONF_DATA_HANDLES.get_handler(str(id(sn)))
            if h is not None:
                info("handler for actual data node triggered")
                if isinstance(h, ConfDataObjectHandler):
                    if ch.change_type == ChangeType.CREATE:
                        h.create(ii, ch)
                    elif ch.change_type == ChangeType.REPLACE:
                        h.replace(ii, ch)
                    elif ch.change_type == ChangeType.DELETE:
                        h.delete(ii, ch)
                if isinstance(h, ConfDataListHandler):
                    if ch.change_type == ChangeType.CREATE:
                        h.create_item(ii, ch)
                    elif ch.change_type == ChangeType.REPLACE:
                        h.replace_item(ii, ch)
                    elif ch.change_type == ChangeType.DELETE:
                        h.delete_item(ii, ch)
            else:
                sn = sn.parent
                while sn is not None:
                    h = CONF_DATA_HANDLES.get_handler(str(id(sn)))
                    if h is not None and isinstance(h, ConfDataObjectHandler):
                        info("handler for superior data node triggered, replace")
                        # print(h.schema_path)
                        # print(h.__class__.__name__)
                        h.replace(ii, ch)
                    if h is not None and isinstance(h, ConfDataListHandler):
                        info("handler for superior data node triggered, replace_item")
                        h.replace_item(ii, ch)
                    sn = sn.parent
        except NonexistentInstance:
            warn("Cannnot notify {}, parent container removed".format(ii))

    # Get data node, evaluate NACM if required
    def get_node_rpc(self, rpc: RpcInfo, staging=False) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)

        if staging:
            try:
                root = self.get_data_root_staging(rpc.username)
            except NoStagingDataException:
                root = self._data
        else:
            root = self._data

        yl_data_request = False
        if (len(ii) > 0) and (isinstance(ii[0], MemberName)):
            # Not getting root
            ns_first = ii[0].namespace
            if (ns_first == "ietf-netconf-acm") and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to access NACM data")
            elif ns_first == "ietf-yang-library":
                root = self._yang_lib_data
                yl_data_request = True
        else:
            # Root node requested
            # Remove NACM data if user is not NACM privieged
            if rpc.username not in CONFIG_NACM["ALLOWED_USERS"]:
                try:
                    root = root.delete_item("ietf-netconf-acm:nacm")
                except NonexistentInstance:
                    pass

            # Append YANG library data
            for member_name, member_val in self._yang_lib_data.value.items():
                root = root.put_member(member_name, member_val)

        # Resolve schema node of the desired data node
        sch_pth_list = filter(lambda isel: isinstance(isel, MemberName), ii)
        sch_pth = DataHelpers.ii2str(sch_pth_list)
        sn = self.get_schema_node(sch_pth)

        state_roots = sn.state_roots()

        # Check if URL points to state data or node that contains state data
        if state_roots and not yl_data_request:
            debug_data("State roots: {}".format(state_roots))
            n = None

            for state_root_sch_pth in state_roots:
                state_root_sn = self._dm.get_data_node(state_root_sch_pth)

                # Check if the desired node is child of the state root
                sni = sn
                is_child = False
                while sni:
                    if sni is state_root_sn:
                        is_child = True
                        break
                    sni = sni.parent

                if is_child:
                    # Direct request for the state data
                    sdh = STATE_DATA_HANDLES.get_handler(state_root_sch_pth)
                    if sdh is not None:
                        if isinstance(sdh, ContainerNodeHandlerBase):
                            state_handler_val = sdh.generate_node(ii, rpc.username, staging)
                            state_root_n = sdh.schema_node.orphan_instance(state_handler_val)
                        elif isinstance(sdh, ListNodeHandlerBase):
                            if (sn is sdh.schema_node) and isinstance(ii[-1], MemberName):
                                state_handler_val = sdh.generate_list(ii, rpc.username, staging)
                                state_root_n = sdh.schema_node.orphan_instance(state_handler_val)
                            else:
                                state_handler_val = sdh.generate_item(ii, rpc.username, staging)
                                state_root_n = sdh.schema_node.orphan_entry(state_handler_val)

                        # Select desired subnode from handler-generated content
                        ii_prefix, ii_rel = sdh.schema_node.split_instance_route(ii)
                        n = state_root_n.goto(ii_rel)

                        # There should be only one state root, no need to continue
                        if len(state_roots) != 1:
                            warn("URI points to directly to state data, but more state roots found")
                        break
                    else:
                        raise NoHandlerForStateDataError(rpc.path)
                else:
                    # Request for config data containing state data
                    n = root.goto(ii)

                    def _fill_state_roots(node: InstanceNode) -> InstanceNode:
                        if isinstance(node.value, ObjectValue):
                            if node.schema_node is state_root_sn.parent:
                                ii_gen = DataHelpers.node_get_ii(node)
                                sdh = STATE_DATA_HANDLES.get_handler(state_root_sch_pth)
                                if sdh is not None:
                                    try:
                                        if isinstance(sdh, ContainerNodeHandlerBase):
                                            state_handler_val = sdh.generate_node(ii_gen, rpc.username, staging)
                                        elif isinstance(sdh, ListNodeHandlerBase):
                                            state_handler_val = sdh.generate_list(ii_gen, rpc.username, staging)
                                    except Exception as e:
                                        error("Error occured in state data generator (sn: {})".format(state_root_sch_pth))
                                        error(epretty(e))
                                        error("This state node will be omitted.")
                                    else:
                                        if state_root_sn.ns == state_root_sn.parent.ns:
                                            nm_name = state_root_sn.qual_name[0]
                                        else:
                                            nm_name = state_root_sn.qual_name[1] + ":" + state_root_sn.qual_name[0]

                                        # print("nm={}".format(nm_name))
                                        node = node.put_member(nm_name, state_handler_val, raw=True).up()
                            else:
                                for key in node:
                                    member = node[key]
                                    node = _fill_state_roots(member).up()
                        elif isinstance(node.value, ArrayValue):
                            i = 0
                            arr_len = len(node.value)
                            while i < arr_len:
                                node = _fill_state_roots(node[i]).up()
                                i += 1

                        return node

                    n = _fill_state_roots(n)
                    root = n.top()
        else:
            # No state data in requested node
            n = root.goto(ii)

        # Process "with-defaults" query parameter
        try:
            with_defs = rpc.qs["with-defaults"][0]
        except (IndexError, KeyError):
            with_defs = None

        if with_defs == "report-all":
            n = n.add_defaults()

        # Evaluate NACM if required
        if self.nacm:
            nrpc = self.nacm.get_user_rules(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_READ) == Action.DENY:
                raise NacmForbiddenError()
            else:
                # Prune nodes that should not be accessible to user
                n = nrpc.prune_data_tree(n, root, ii, Permission.NACM_ACCESS_READ)

        # Process "depth" query parameter
        try:
            max_depth_str = rpc.qs["depth"][0]
            if max_depth_str == "unbounded":
                max_depth = None
            else:
                max_depth = int(max_depth_str) - 1
                if (max_depth < 0) or (max_depth > 65535):
                    raise ValueError()
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

        # Return result
        return n

    # Create new data node
    def create_node_rpc(self, root: InstanceNode, rpc: RpcInfo, value: Any) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)

        # Get target member name
        input_member_keys = tuple(value.keys())
        if len(input_member_keys) != 1:
            raise ValueError("Received json object must contain exactly one member")

        input_member_name_fq = input_member_keys[0]
        try:
            input_member_ns, input_member_name = input_member_name_fq.split(":", maxsplit=1)
        except ValueError:
            raise ValueError("Input object name must me in fully-qualified format")
        input_member_value = value[input_member_name_fq]

        # Deny any changes of NACM data for non-privileged users
        if (len(ii) > 0) and (isinstance(ii[0], MemberName)):
            # Not getting root
            ns_first = ii[0].namespace
            if (ns_first == "ietf-netconf-acm") and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to modify NACM data")
        else:
            # Editing root node
            if (input_member_ns == "ietf-netconf-acm") and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to modify NACM data")

        # Evaluate NACM
        if self.nacm:
            nrpc = self.nacm.get_user_rules(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_CREATE) == Action.DENY:
                raise NacmForbiddenError()

        n = root.goto(ii)

        # Get target schema node
        sn = n.schema_node  # type: InternalNode
        member_sn = sn.get_child(input_member_name)

        # Check if target member already exists
        if sn.ns == member_sn.ns:
            try:
                existing_member = n[input_member_name]
            except NonexistentInstance:
                existing_member = None
        else:
            try:
                existing_member = n[input_member_name_fq]
            except NonexistentInstance:
                existing_member = None

        # Get query parameters
        insert = rpc.qs.get("insert", [None])[0]
        point = rpc.qs.get("point", [None])[0]

        if isinstance(member_sn, ListNode):
            # Append received node to list

            # Create list if necessary
            if existing_member is None:
                existing_member = n.put_member(input_member_name, ArrayValue([]))

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_item = member_sn.entry_from_raw(input_member_value)

            # Get ListNode key names
            list_node_keys = member_sn.keys     # Key names in the form [(key, ns), ]

            if insert == "first":
                # Optimization
                if len(existing_member.value) > 0:
                    list_entry_first = existing_member[0]   # type: ArrayEntry
                    new_member = list_entry_first.insert_before(new_value_item).up()
                else:
                    new_member = existing_member.update([new_value_item])
            elif (insert == "last") or (insert is None):
                # Optimization
                if len(existing_member.value) > 0:
                    list_entry_last = existing_member[-1]   # type: ArrayEntry
                    new_member = list_entry_last.insert_after(new_value_item).up()
                else:
                    new_member = existing_member.update([new_value_item])
            elif (insert == "before") and (point is not None):
                point_keys_val = point.split(",")  # List key values passed in the "point" query argument
                if len(list_node_keys) != len(point_keys_val):
                    raise ValueError(
                        "Invalid number of keys passed in 'point' query: {} ({} expected)".format(
                            len(point_keys_val), len(list_node_keys)
                        )
                    )
                entry_keys = dict(map(lambda i: (list_node_keys[i], point_keys_val[i]), range(len(list_node_keys))))
                entry_sel = EntryKeys(entry_keys)
                point_list_entry = entry_sel.goto_step(existing_member)   # type: ArrayEntry
                new_member = point_list_entry.insert_before(new_value_item).up()
            elif (insert == "after") and (point is not None):
                point_keys_val = point.split(",")  # List key values passed in the "point" query argument
                if len(list_node_keys) != len(point_keys_val):
                    raise ValueError(
                        "Invalid number of keys passed in 'point' query: {} ({} expected)".format(
                            len(point_keys_val), len(list_node_keys)
                        )
                    )
                entry_keys = dict(map(lambda i: (list_node_keys[i], point_keys_val[i]), range(len(list_node_keys))))
                entry_sel = EntryKeys(entry_keys)
                point_list_entry = entry_sel.goto_step(existing_member)   # type: ArrayEntry
                new_member = point_list_entry.insert_after(new_value_item).up()
            else:
                raise ValueError("Invalid 'insert'/'point' query values")
        elif isinstance(member_sn, LeafListNode):
            # Append received node to leaf list

            # Create leaf list if necessary
            if existing_member is None:
                existing_member = n.put_member(input_member_name, ArrayValue([]))

            # Convert input data from List/Dict to ArrayValue/ObjectValue
            new_value_item = member_sn.entry_from_raw(input_member_value)

            if insert == "first":
                new_member = existing_member.update(ArrayValue([new_value_item] + existing_member.value))
            elif (insert == "last") or (insert is None):
                new_member = existing_member.update(ArrayValue(existing_member.value + [new_value_item]))
            else:
                raise ValueError("Invalid 'insert' query value")
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
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        # Deny any changes of NACM data for non-privileged users
        if (len(ii) > 0) and (isinstance(ii[0], MemberName)):
            # Not getting root
            ns_first = ii[0].namespace
            if (ns_first == "ietf-netconf-acm") and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to modify NACM data")
        else:
            # Replacing root node
            # Check if NACM data are present in the datastore
            nacm_val = n.value.get("ietf-netconf-acm:nacm")
            if (nacm_val is not None) and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to modify NACM data")

        # Evaluate NACM
        if self.nacm:
            nrpc = self.nacm.get_user_rules(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_UPDATE) == Action.DENY:
                raise NacmForbiddenError()

        new_n = n.update(value, raw=True)

        return new_n.top()

    # Delete data node
    def delete_node_rpc(self, root: InstanceNode, rpc: RpcInfo) -> InstanceNode:
        ii = self.parse_ii(rpc.path, rpc.path_format)
        n = root.goto(ii)

        # Deny any changes of NACM data for non-privileged users
        if (len(ii) > 0) and (isinstance(ii[0], MemberName)):
            # Not getting root
            ns_first = ii[0].namespace
            if (ns_first == "ietf-netconf-acm") and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to modify NACM data")
        else:
            # Deleting root node
            # Check if NACM data are present in the datastore
            nacm_val = n.value.get("ietf-netconf-acm:nacm")
            if (nacm_val is not None) and (rpc.username not in CONFIG_NACM["ALLOWED_USERS"]):
                raise NacmForbiddenError(rpc.username + " not allowed to modify NACM data")

        # Evaluate NACM
        if self.nacm:
            nrpc = self.nacm.get_user_rules(rpc.username)
            if nrpc.check_data_node_permission(root, ii, Permission.NACM_ACCESS_DELETE) == Action.DENY:
                raise NacmForbiddenError()

        if len(ii) == 0:
            # Deleting entire datastore
            new_n = RootNode(ObjectValue({}), root.schema_node, datetime.now())
        else:
            n_parent = n.up()
            last_isel = ii[-1]
            if isinstance(n_parent.value, ArrayValue):
                if isinstance(last_isel, EntryIndex):
                    new_n = n_parent.delete_item(last_isel.index)
                elif isinstance(last_isel, EntryKeys):
                    new_n = n_parent.delete_item(n.index)
                else:
                    raise ValueError("Unknown node selector")
            elif isinstance(n_parent.value, ObjectValue):
                new_n = n_parent.delete_item(last_isel.namespace + ":" + last_isel.name if last_isel.namespace else last_isel.name)
            else:
                raise InstanceValueError(rpc.path, "Invalid target node type")

        return new_n.top()

    # Invoke an operation
    def invoke_op_rpc(self, rpc: RpcInfo) -> JsonNodeT:
        if rpc.op_name == "jetconf:conf-start":
            try:
                cl_name = rpc.op_input_args["name"]
            except (TypeError, KeyError):
                raise ValueError("This operation expects \"name\" input parameter")

            transaction_opts = rpc.op_input_args.get("options")

            if self._usr_journals.get(rpc.username) is None:
                self._usr_journals[rpc.username] = UsrChangeJournal(self._data, transaction_opts)

            self._usr_journals[rpc.username].cl_new(cl_name)

            ret_data = {"status": "OK"}
        elif rpc.op_name == "jetconf:conf-list":
            usr_journal = self._usr_journals.get(rpc.username)
            if usr_journal is not None:
                chl_json = usr_journal.list()
            else:
                chl_json = str(None)

            ret_data = {
                "status": "OK",
                "changelists": chl_json
            }
        elif rpc.op_name == "jetconf:conf-drop":
            usr_journal = self._usr_journals.get(rpc.username)
            if usr_journal is not None:
                if not usr_journal.cl_drop():
                    del self._usr_journals[rpc.username]

            ret_data = {"status": "OK"}
        elif rpc.op_name == "jetconf:conf-commit":
            usr_journal = self._usr_journals.get(rpc.username)
            if usr_journal is not None:
                try:
                    self.lock_data(rpc.username)
                    usr_journal.commit(self)
                    if CONFIG["GLOBAL"]["PERSISTENT_CHANGES"] is True:
                        self.save()
                finally:
                    self.unlock_data()

                del self._usr_journals[rpc.username]

                ret_data = {
                    "status": "OK",
                    "conf-changed": True
                }
            else:
                info("[{}]: Nothing to commit".format(rpc.username))
                ret_data = {
                    "status": "OK",
                    "conf-changed": False
                }
        elif rpc.op_name == "jetconf:get-schema-digest":
            ret_data = self._dm.schema_digest()
        elif rpc.op_name == "jetconf:get-list-length":
            try:
                list_url = rpc.op_input_args["url"]     # type: str
            except (TypeError, KeyError):
                raise ValueError("This operation expects \"url\" input parameter")

            if list_url == "":
                list_ii = []
            else:
                list_ii = self.parse_ii(list_url, PathFormat.URL)

            ln_val = self._data.goto(list_ii).value
            if isinstance(ln_val, list):
                ret_data = {"jetconf:list-length": len(ln_val)}
            else:
                raise ValueError("Passed URI does not point to List")
        else:
            # External operation defined in data model
            if self.nacm and (not rpc.skip_nacm_check):
                nrpc = self.nacm.get_user_rules(rpc.username)
                if nrpc.check_rpc_name(rpc.op_name) == Action.DENY:
                    raise NacmForbiddenError(
                        "Op \"{}\" invocation denied for user \"{}\"".format(rpc.op_name, rpc.username)
                    )

            op_handler = OP_HANDLERS.get_handler(rpc.op_name)
            if op_handler is None:
                raise NoHandlerForOpError(rpc.op_name)

            # Get operation input schema
            sn = self._dm.get_schema_node(rpc.path)
            sn_input = sn.get_child("input")

            # if sn_input is not None:
            #     print("RPC input schema:")
            #     print(sn_input._ascii_tree(""))

            if sn_input.children:
                # Input arguments are expected
                op_input_args = sn_input.from_raw(rpc.op_input_args)
                try:
                    ret_data = op_handler(op_input_args, rpc.username)
                except Exception as e:
                    raise OpHandlerFailedError(epretty(e))
            else:
                # Operation with no input
                try:
                    ret_data = op_handler(None, rpc.username)
                except Exception as e:
                    raise OpHandlerFailedError(epretty(e))

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
