import collections
import copy
from io import StringIO
from threading import Lock
from enum import Enum
from colorlog import error, info
from typing import List, Set

from yangson.instance import (
    InstanceNode,
    NonexistentSchemaNode,
    NonexistentInstance,
    ArrayValue,
    ObjectValue,
    InstanceSelector,
    InstanceRoute,
    MemberName,
    EntryIndex,
    EntryKeys
)

from .helpers import DataHelpers, ErrorHelpers, LogHelpers, PathFormat

epretty = ErrorHelpers.epretty
debug_nacm = LogHelpers.create_module_dbg_logger(__name__)


class Action(Enum):
    PERMIT = True
    DENY = False


class Permission(Enum):
    NACM_ACCESS_READ = 0
    NACM_ACCESS_CREATE = 1
    NACM_ACCESS_UPDATE = 2
    NACM_ACCESS_DELETE = 3
    NACM_ACCESS_EXEC = 4


class NacmRuleType(Enum):
    NACM_RULE_NOTSET = 0
    NACM_RULE_OPERATION = 1
    NACM_RULE_NOTIF = 2
    NACM_RULE_DATA = 3


class NonexistentUserError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class NacmGroup:
    def __init__(self, name: str, users: List[str]):
        self.name = name
        self.users = users


class NacmRule:
    class TypeData:
        def __init__(self):
            self.path = None        # type: str
            self.rpc_names = None   # type: List[str]
            self.ntf_names = None   # type: List[str]

    def __init__(self):
        self.name = None                            # type: str
        self.comment = None                         # type: str
        self.module = None                          # type: str
        self.type = NacmRuleType.NACM_RULE_NOTSET   # type: NacmRuleType
        self.type_data = self.TypeData()
        self.access = set()                         # type: Set[Permission]
        self.action = Action.DENY


class RuleTreeNode:
    def __init__(self, isel: InstanceSelector=None, up: "RuleTreeNode"=None):
        self.isel = isel
        self.rule = None    # type: NacmRule
        self.up = up
        self.children = []  # type: List[RuleTreeNode]

    def get_rule(self, perm: Permission) -> NacmRule:
        n = self
        while n:
            if (n.rule is not None) and (perm in n.rule.access):
                return n.rule
            n = n.up

        return None

    def get_action(self, perm: Permission) -> Action:
        rule = self.get_rule(perm)
        return rule.action if rule is not None else None


class NacmRuleList:
    def __init__(self):
        self.name = ""          # type: str
        self.groups = []        # type: List[NacmGroup]
        self.rules = []         # type: List[NacmRule]


class DataRuleTree:
    def __init__(self, rule_lists: List[NacmRuleList]):
        self.root = []  # type: List[RuleTreeNode]

        for rl in rule_lists:
            for rule in filter(lambda r: r.type == NacmRuleType.NACM_RULE_DATA, rl.rules):
                try:
                    ii = DataHelpers.parse_ii(rule.type_data.path, PathFormat.XPATH)
                except NonexistentSchemaNode as e:
                    error(epretty(e, __name__))
                    ii = []
                nl = self.root
                node_match_prev = None
                for isel in ii:
                    node_match = (list(filter(lambda x: x.isel == isel, nl)) or [None])[0]
                    if node_match is None:
                        new_elem = RuleTreeNode()
                        new_elem.isel = isel
                        new_elem.up = node_match_prev

                        if isel is ii[-1]:
                            new_elem.rule = rule
                        nl.append(new_elem)
                        node_match_prev = new_elem
                        nl = new_elem.children
                    else:
                        if isel is ii[-1]:
                            node_match.rule = rule
                        node_match_prev = node_match
                        nl = node_match.children

    def _print_rule_tree(self, io_str: StringIO, rule_node_list: List[RuleTreeNode], depth: int, vbars: List[int]):
        ind_str = ("   " * depth) + "+--"

        for vb in vbars:
            isl = list(ind_str)
            isl[vb * 3] = "|"
            ind_str = "".join(isl)

        for rule_node in rule_node_list:
            action = rule_node.get_action(Permission.NACM_ACCESS_READ)
            action_str = str(action.name) if action is not None else ""
            io_str.write(ind_str + " " + str(rule_node.isel) + " " + action_str + "\n")
            if rule_node is rule_node_list[-1]:
                self._print_rule_tree(io_str, rule_node.children, depth + 1, vbars)
            else:
                self._print_rule_tree(io_str, rule_node.children, depth + 1, vbars + [depth])

    def print_rule_tree(self) -> str:
        io_str = StringIO()
        io_str.write("----- NACM Data Rule tree -----\n")
        self._print_rule_tree(io_str, self.root, 0, [])
        return io_str.getvalue()


class NacmConfig:
    def __init__(self, nacm_ds: "BaseDatastore"):
        self.nacm_ds = nacm_ds
        self.enabled = False
        self.default_read = Action.PERMIT
        self.default_write = Action.PERMIT
        self.default_exec = Action.PERMIT
        self.nacm_groups = []
        self.rule_lists = []
        self._user_nacm_rpc = {}
        self.internal_data_lock = Lock()
        self._lock_username = None

    # Fills internal read-only data structures
    def update(self):
        lock_res = self.internal_data_lock.acquire(blocking=True, timeout=1)
        if not lock_res:
            error("NACM update: cannot acquire data lock")
            return

        self.nacm_groups = []
        self.rule_lists = []
        self._user_nacm_rpc = {}

        try:
            nacm_json = self.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm").value
        except NonexistentInstance:
            raise ValueError("Data does not contain \"ietf-netconf-acm:nacm\" root element")

        self.enabled = nacm_json["enable-nacm"]
        if not self.enabled:
            # NACM not enabled, no need to continue
            self.internal_data_lock.release()
            return

        self.default_read = Action.PERMIT if nacm_json["read-default"] == "permit" else Action.DENY
        self.default_write = Action.PERMIT if nacm_json["write-default"] == "permit" else Action.DENY
        self.default_exec = Action.PERMIT if nacm_json["exec-default"] == "permit" else Action.DENY

        for group in nacm_json["groups"]["group"]:
            self.nacm_groups.append(NacmGroup(group["name"], group["user-name"]))

        for rule_list_json in nacm_json["rule-list"]:
            rl = NacmRuleList()
            rl.name = rule_list_json["name"]
            rl.groups = rule_list_json["group"]

            for rule_json in rule_list_json["rule"]:
                rule = NacmRule()
                rule.name = rule_json.get("name")
                rule.comment = rule_json.get("comment")
                rule.module = rule_json.get("module-name")

                if rule_json.get("access-operations") is not None:
                    access_perm_list = rule_json["access-operations"]
                    if isinstance(access_perm_list, str) and (access_perm_list == "*"):
                        rule.access = set(Permission)
                    elif isinstance(access_perm_list, collections.Iterable):
                        def perm_str2enum(perm_str: str):
                            return {
                                "read": Permission.NACM_ACCESS_READ,
                                "create": Permission.NACM_ACCESS_CREATE,
                                "update": Permission.NACM_ACCESS_UPDATE,
                                "delete": Permission.NACM_ACCESS_DELETE,
                                "exec": Permission.NACM_ACCESS_EXEC,
                            }.get(perm_str)
                        rule.access.update(map(perm_str2enum, access_perm_list))

                if rule_json.get("rpc-name") is not None:
                    if rule.type != NacmRuleType.NACM_RULE_NOTSET:
                        error("Invalid rule definition (multiple cases from rule-type choice): \"{}\"".format(rule.name))
                    else:
                        rule.type = NacmRuleType.NACM_RULE_OPERATION
                        rule.type_data.rpc_names = rule_json.get("rpc-name").split()

                if rule_json.get("notification-name") is not None:
                    if rule.type != NacmRuleType.NACM_RULE_NOTSET:
                        error("Invalid rule definition (multiple cases from rule-type choice): \"{}\"".format(rule.name))
                    else:
                        rule.type = NacmRuleType.NACM_RULE_NOTIF
                        rule.type_data.ntf_names = rule_json.get("notification-name").split()

                if rule_json.get("path") is not None:
                    if rule.type != NacmRuleType.NACM_RULE_NOTSET:
                        error("Invalid rule definition (multiple cases from rule-type choice): \"{}\"".format(rule.name))
                    else:
                        rule.type = NacmRuleType.NACM_RULE_DATA
                        rule.type_data.path = rule_json["path"]

                rule.action = Action.PERMIT if rule_json["action"] == "permit" else Action.DENY
                rl.rules.append(rule)

            self.rule_lists.append(rl)

        self.internal_data_lock.release()

    def create_user_nacm(self, username: str):
        # all_users = set()
        # for gr in self.nacm_groups:
        #     for user in gr.users:
        #         all_users.add(user)

        # for user in all_users:
        #     info("Creating personalized rule list for user \"{}\"".format(user))
        #     self._user_nacm_rpc[user] = UserNacm(self, user)
        # if username not in all_users:
        #     raise NonexistentUserError

        if not self.internal_data_lock.acquire(blocking=True, timeout=1):
            error("Cannot acquire NACM config lock ")
            return

        info("Creating personalized rule list for user \"{}\"".format(username))
        self._user_nacm_rpc[username] = UserNacm(self, username)

        self.internal_data_lock.release()

    def get_user_nacm(self, username: str) -> "UserNacm":
        user_nacm = self._user_nacm_rpc.get(username)
        if user_nacm is None:
            self.create_user_nacm(username)
            user_nacm = self._user_nacm_rpc.get(username)

        return user_nacm


# Rules for particular user
class UserNacm:
    def __init__(self, config: NacmConfig, username: str):
        self.nacm_enabled = config.enabled
        self.default_read = config.default_read
        self.default_write = config.default_write
        self.default_exec = config.default_exec
        self.rule_lists = []

        user_groups = list(filter(lambda x: username in x.users, config.nacm_groups))
        user_groups_names = list(map(lambda x: x.name, user_groups))
        self.rule_lists = list(filter(lambda x: (set(user_groups_names) & set(x.groups)), config.rule_lists))

        self.rule_tree = DataRuleTree(self.rule_lists)
        debug_nacm("Rule tree for user \"{}\":\n{}".format(username, self.rule_tree.print_rule_tree()))

    def check_data_node_path(self, root: InstanceNode, ii: InstanceRoute, access: Permission, out_matching_rule: List[NacmRule]=None) -> Action:
        if not self.nacm_enabled:
            return Action.PERMIT

        retval = None
        data_node = root   # type: InstanceNode

        nl = self.rule_tree.root
        for isel in ii:
            node_match = None
            for rule_node in nl:
                if (type(rule_node.isel) == type(isel)) and (rule_node.isel == isel):
                    node_match = rule_node
                    break

                if isinstance(isel, EntryIndex) and isinstance(rule_node.isel, EntryKeys):
                    if isel.peek_step(data_node.value) is rule_node.isel.peek_step(data_node.value):
                        node_match = rule_node
                        break

            data_node = isel.goto_step(data_node)

            if node_match:
                matching_rule = node_match.get_rule(access)
                retval = matching_rule.action if matching_rule else None
                if (matching_rule is not None) and (out_matching_rule is not None):
                    out_matching_rule.insert(0, matching_rule)
                nl = node_match.children
            else:
                break

        if retval is None:
            # No matching rule
            if access in {Permission.NACM_ACCESS_READ}:
                retval = self.default_read
            else:
                retval = self.default_write

        debug_nacm("check_data_node_path, result = {}".format(retval.name))
        return retval

    def _check_data_read_path(self, node: InstanceNode, root: InstanceNode, ii: InstanceRoute) -> InstanceNode:
        if isinstance(node.value, ObjectValue):
            # print("obj: {}".format(node.value))
            for child_key in sorted(node.value.keys()):
                nsel = MemberName(child_key)
                m = nsel.goto_step(node)
                mii = copy.copy(ii)
                mii.append(nsel)

                debug_nacm("checking mii {}".format(mii))
                if self.check_data_node_path(root, mii, Permission.NACM_ACCESS_READ) == Action.DENY:
                    # debug_nacm("Pruning node {} {}".format(id(node.value[child_key]), node.value[child_key]))
                    debug_nacm("Pruning node {}".format(mii))
                    node = node.delete_member(child_key)
                else:
                    node = self._check_data_read_path(m, root, mii).up()
        elif isinstance(node.value, ArrayValue):
            # print("array: {}".format(node.value))
            i = 0
            arr_len = len(node.value)
            while i < arr_len:
                nsel = EntryIndex(i)
                e = nsel.goto_step(node)
                eii = copy.copy(ii)
                eii.append(nsel)

                debug_nacm("checking eii {}".format(eii))
                if self.check_data_node_path(root, eii, Permission.NACM_ACCESS_READ) == Action.DENY:
                    # debug_nacm("Pruning node {} {}".format(id(node.value[i]), node.value[i]))
                    debug_nacm("Pruning node {}".format(eii))
                    node = node.delete_entry(i)
                    arr_len -= 1
                else:
                    i += 1
                    node = self._check_data_read_path(e, root, eii).up()

        return node

    def check_data_read_path(self, node: InstanceNode, root: InstanceNode, ii: InstanceRoute) -> InstanceNode:
        if not self.nacm_enabled:
            return node
        else:
            return self._check_data_read_path(node, root, ii)

    def check_rpc_name(self, rpc_name: str, out_matching_rule: List[NacmRule] = None) -> Action:
        if not self.nacm_enabled:
            return Action.PERMIT

        for rl in self.rule_lists:
            for rpc_rule in filter(lambda r: r.type == NacmRuleType.NACM_RULE_OPERATION, rl.rules):
                if rpc_name in rpc_rule.type_data.rpc_names:
                    if out_matching_rule is not None:
                        out_matching_rule.append(rpc_rule)
                    return rpc_rule.action

        return self.default_exec


def test():
    error("Tests moved to tests/tests_jetconf.py")
