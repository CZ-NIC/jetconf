import collections
from io import StringIO
from threading import Lock
from enum import Enum

from colorlog import error, info
from typing import List, Set, Optional

from yangson.datamodel import DataModel
from yangson.instvalue import ArrayValue, ObjectValue
from yangson.instance import (
    InstanceNode,
    NonexistentSchemaNode,
    NonexistentInstance,
    InstanceRoute,
    MemberName,
    EntryIndex,
    EntryKeys
)

from .helpers import DataHelpers, ErrorHelpers, LogHelpers

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
    def __init__(self, isel=None, up: "RuleTreeNode"=None):
        self.isel = isel
        self.rule = None    # type: NacmRule
        self.up = up
        self.children = []  # type: List[RuleTreeNode]

    def get_rule(self, perm: Permission) -> Optional[NacmRule]:
        n = self
        while n:
            if (n.rule is not None) and (perm in n.rule.access):
                return n.rule
            n = n.up

        return None

    def get_action(self, perm: Permission) -> Optional[Action]:
        rule = self.get_rule(perm)
        return rule.action if rule is not None else None


class NacmRuleList:
    def __init__(self):
        self.name = ""          # type: str
        self.groups = []        # type: List[NacmGroup]
        self.rules = []         # type: List[NacmRule]


class DataRuleTree:
    def __init__(self, dm: DataModel, rule_lists: List[NacmRuleList]):
        self.root = []  # type: List[RuleTreeNode]

        for rl in rule_lists:
            for rule in filter(lambda r: r.type == NacmRuleType.NACM_RULE_DATA, rl.rules):
                try:
                    ii = dm.parse_instance_id(rule.type_data.path)
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
        indent_str_list = list(("   " * depth) + "+--")
        for vb in vbars:
            indent_str_list[vb * 3] = "|"
        indent_str = "".join(indent_str_list)

        for rule_node in rule_node_list:
            rule = rule_node.rule
            if rule is not None:
                action_str = rule.action.name
                access = sorted(list(map(lambda n: n.name.split("_")[-1].lower(), rule.access)))
                io_str.write(indent_str + " " + str(rule_node.isel) + " " + action_str + str(access) + "\n")
            else:
                io_str.write(indent_str + " " + str(rule_node.isel) + "\n")
            if rule_node is rule_node_list[-1]:
                self._print_rule_tree(io_str, rule_node.children, depth + 1, vbars)
            else:
                self._print_rule_tree(io_str, rule_node.children, depth + 1, vbars + [depth])

    def __str__(self) -> str:
        io_str = StringIO()
        io_str.write("----- NACM Data Rule tree -----\n")
        self._print_rule_tree(io_str, self.root, 0, [])
        return io_str.getvalue()


class NacmConfig:
    def __init__(self, nacm_ds: "BaseDatastore", dm: DataModel):
        self.nacm_ds = nacm_ds
        self.dm = dm
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
        self.enabled = False

        try:
            nacm_n = self.nacm_ds.get_data_root()["ietf-netconf-acm:nacm"]
        except NonexistentInstance:
            debug_nacm("Data does not contain \"/ietf-netconf-acm:nacm\" branch, NACM will not be enabled")
            return

        nacm_json = nacm_n.add_defaults().value
        self.enabled = nacm_json["enable-nacm"]

        if not self.enabled:
            # NACM not enabled, no need to continue
            self.internal_data_lock.release()
            return

        self.default_read = Action.PERMIT if nacm_json["read-default"] == "permit" else Action.DENY
        self.default_write = Action.PERMIT if nacm_json["write-default"] == "permit" else Action.DENY
        self.default_exec = Action.PERMIT if nacm_json["exec-default"] == "permit" else Action.DENY

        for group in nacm_json.get("groups", {}).get("group", []):
            self.nacm_groups.append(NacmGroup(group["name"], group["user-name"]))

        for rule_list_json in nacm_json.get("rule-list", []):
            rl = NacmRuleList()
            rl.name = rule_list_json["name"]
            rl.groups = rule_list_json["group"]

            for rule_json in rule_list_json.get("rule", []):
                rule = NacmRule()
                rule.name = rule_json.get("name")
                rule.comment = rule_json.get("comment")
                rule.module = rule_json.get("module-name")

                if rule_json.get("access-operations") is not None:
                    access_perm_list = rule_json["access-operations"]
                    if isinstance(access_perm_list, str) and (access_perm_list == "*"):
                        rule.access = set(Permission)
                    elif isinstance(access_perm_list, collections.Iterable):
                        perm_str2enum = {
                            "read": Permission.NACM_ACCESS_READ,
                            "create": Permission.NACM_ACCESS_CREATE,
                            "update": Permission.NACM_ACCESS_UPDATE,
                            "delete": Permission.NACM_ACCESS_DELETE,
                            "exec": Permission.NACM_ACCESS_EXEC,
                        }
                        rule.access.update(map(lambda x: perm_str2enum[x], access_perm_list))

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
        self._user_nacm_rpc[username] = UserRuleSet(self.dm, self, username)

        self.internal_data_lock.release()

    def get_user_rules(self, username: str) -> "UserRuleSet":
        user_nacm = self._user_nacm_rpc.get(username)
        if user_nacm is None:
            self.create_user_nacm(username)
            user_nacm = self._user_nacm_rpc.get(username)

        return user_nacm


# Rules for particular user
class UserRuleSet:
    def __init__(self, dm: DataModel, config: NacmConfig, username: str):
        self.nacm_enabled = config.enabled
        self.default_read = config.default_read
        self.default_write = config.default_write
        self.default_exec = config.default_exec
        self.rule_lists = []
        self.rule_tree = None

        if not self.nacm_enabled:
            return

        user_groups = list(filter(lambda x: username in x.users, config.nacm_groups))
        user_groups_names = list(map(lambda x: x.name, user_groups))
        self.rule_lists = list(filter(lambda x: (set(user_groups_names) & set(x.groups)), config.rule_lists))

        self.rule_tree = DataRuleTree(dm, self.rule_lists)
        debug_nacm("Rule tree for user \"{}\":\n{}".format(username, str(self.rule_tree)))

    def check_data_node_permission(self, root: InstanceNode, ii: InstanceRoute, access: Permission) -> Action:
        if not self.nacm_enabled:
            return Action.PERMIT

        data_node_value = (root.value, root.schema_node)

        nl = self.rule_tree.root        # type: List[RuleTreeNode]
        node_match = None               # type: RuleTreeNode
        for isel in ii:
            # Find child by instance selector
            node_match_step = None      # type: RuleTreeNode
            for rule_node in nl:
                if (type(rule_node.isel) == type(isel)) and (rule_node.isel == isel):
                    node_match_step = rule_node
                    break

                if isinstance(isel, EntryIndex) and isinstance(rule_node.isel, EntryKeys) and \
                        (isel.peek_step(*data_node_value)[0] is rule_node.isel.peek_step(*data_node_value)[0]):
                    node_match_step = rule_node
                    break

            if node_match_step:
                nl = node_match_step.children
                node_match = node_match_step
                data_node_value = isel.peek_step(*data_node_value)
            else:
                break

        if node_match is not None:
            # Matching rule found
            retval = node_match.get_action(access)
        else:
            # No matching rule, return default action
            retval = self.default_read if access == Permission.NACM_ACCESS_READ else self.default_write

        # debug_nacm("check_data_node_path, result = {}".format(retval.name))
        return retval

    def _prune_data_tree(self, node: InstanceNode, root: InstanceNode, ii: InstanceRoute, access: Permission) -> InstanceNode:
        if isinstance(node.value, ObjectValue):
            # print("obj: {}".format(node.value))
            nsel = MemberName(name="", ns=None)
            mii = ii + [nsel]
            for child_key in node.value.keys():
                key_splitted = child_key.split(":", maxsplit=1)
                if len(key_splitted) > 1:
                    nsel.namespace, nsel.name = key_splitted
                else:
                    nsel.namespace, nsel.name = (None, key_splitted[0])
                m = nsel.goto_step(node)

                # debug_nacm("checking mii {}".format(mii))
                if self.check_data_node_permission(root, mii, access) == Action.DENY:
                    # debug_nacm("Pruning node {} {}".format(id(node.value[child_key]), node.value[child_key]))
                    debug_nacm("Pruning node {}".format(DataHelpers.ii2str(mii)))
                    node = node.delete_item(child_key)
                else:
                    node = self._prune_data_tree(m, root, mii, access).up()
        elif isinstance(node.value, ArrayValue):
            # print("array: {}".format(node.value))
            nsel = EntryIndex(0)
            eii = ii + [nsel]
            i = 0
            arr_len = len(node.value)
            while i < arr_len:
                nsel.index = i
                e = nsel.goto_step(node)

                # debug_nacm("checking eii {}".format(eii))
                if self.check_data_node_permission(root, eii, access) == Action.DENY:
                    # debug_nacm("Pruning node {} {}".format(id(node.value[i]), node.value[i]))
                    debug_nacm("Pruning node {}".format(DataHelpers.ii2str(eii)))
                    node = node.delete_item(i)
                    arr_len -= 1
                else:
                    i += 1
                    node = self._prune_data_tree(e, root, eii, access).up()

        return node

    def prune_data_tree(self, node: InstanceNode, root: InstanceNode, ii: InstanceRoute, access: Permission) -> InstanceNode:
        if not self.nacm_enabled:
            return node
        else:
            return self._prune_data_tree(node, root, ii, access)

    def check_rpc_name(self, rpc_name: str) -> Action:
        if not self.nacm_enabled:
            return Action.PERMIT

        for rl in self.rule_lists:
            for rpc_rule in filter(lambda r: r.type == NacmRuleType.NACM_RULE_OPERATION, rl.rules):
                if rpc_name in rpc_rule.type_data.rpc_names:
                    return rpc_rule.action

        return self.default_exec
