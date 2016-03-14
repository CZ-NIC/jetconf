import json
import collections
import logging
from threading import Lock

import colorlog
import copy
import sys
from enum import Enum
from colorlog import error, warning as warn, info, debug
from typing import List, Any, Dict, TypeVar, Tuple, Set
import yangson.instance
from yangson.instance import Instance, NonexistentInstance, ArrayValue, ObjectValue, InstanceSelector, InstanceIdentifier
from yangson.schema import NonexistentSchemaNode

JsonNodeT = Dict[str, Any]


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
            self.path = None  # type: str
            self.rpc_names = None
            self.ntf_names = None

    def __init__(self):
        self.name = None
        self.comment = None
        self.module = None
        # NacmRuleType
        self.type = NacmRuleType.NACM_RULE_NOTSET
        # path, rpc_names, ntf_names
        self.type_data = self.TypeData()
        # Permission
        self.access = set()
        self.action = Action.DENY


class RuleTreeNode:
    def __init__(self, isel: InstanceSelector=None, up: "RuleTreeNode"=None):
        self.isel = isel
        self.rule = None    # type: NacmRule
        self.up = up
        self.children = []  # type: List[RuleTreeNode]

    def get_action(self, perm: Permission) -> Action:
        n = self
        while n:
            if (n.rule is not None) and (perm in n.rule.access):
                return n.rule.action
            n = n.up

        return None


class NacmRuleList:
    def __init__(self):
        self.name = ""
        self.groups = []
        self.rules = []
        self.rule_tree = []   # type: List[RuleTreeNode]

    def _print_rule_tree(self, rule_node_list: List[RuleTreeNode], depth: int = 0, vbars=[]):
        if depth == 0:
            print("----- Rule tree of rule list \"{}\": -----".format(self.name))

        ind_str = ""
        d = depth
        while d:
            ind_str += "   "
            d -= 1

        ind_str += "+--"

        # :o) :o) :o)
        for vb in vbars:
            isl = list(ind_str)
            isl[vb * 3] = "|"
            ind_str = "".join(isl)

        for rule_node in rule_node_list:
            action = rule_node.get_action(Permission.NACM_ACCESS_READ)
            action_str = str(action.name) if action is not None else ""
            print(ind_str + " " + str(rule_node.isel) + " " + action_str)
            if rule_node is rule_node_list[-1]:
                self._print_rule_tree(rule_node.children, depth + 1, vbars)
            else:
                self._print_rule_tree(rule_node.children, depth + 1, vbars + [depth])

    def print_rule_tree(self):
        self._print_rule_tree(self.rule_tree)


class NacmConfig:
    def __init__(self, nacm_ds: "BaseDatastore"):
        self.nacm_ds = nacm_ds
        self.enabled = False
        self.default_read = Action.PERMIT
        self.default_write = Action.PERMIT
        self.default_exec = Action.PERMIT
        self.nacm_groups = []
        self.rule_lists = []
        self._data_lock = Lock()
        self._lock_username = None

        try:
            self.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm")
        except NonexistentInstance:
            raise ValueError("Data does not contain \"ietf-netconf-acm:nacm\" root element")

        self.update(self.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm"))

    # Fills internal read-only data structures
    def update(self, nacm_data: Instance):
        nacm_json = nacm_data.value
        self.enabled = nacm_json["enable-nacm"]
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
                    access_perm_list = rule_json["access-operations"].split()
                    for access_perm_str in access_perm_list:
                        access_perm = {
                            "read": Permission.NACM_ACCESS_READ,
                            "create": Permission.NACM_ACCESS_CREATE,
                            "update": Permission.NACM_ACCESS_UPDATE,
                            "delete": Permission.NACM_ACCESS_DELETE,
                            "exec": Permission.NACM_ACCESS_EXEC,
                            "*": set(Permission),
                        }.get(access_perm_str)
                        if access_perm is not None:
                            if isinstance(access_perm, collections.Iterable):
                                rule.access.update(access_perm)
                            else:
                                rule.access.add(access_perm)

                if rule_json.get("rpc-name") is not None:
                    if rule.type != NacmRuleType.NACM_RULE_NOTSET:
                        error(
                                "Invalid rule definition (multiple cases from rule-type choice): \"{}\"".format(
                                        rule.name))
                    else:
                        rule.type = NacmRuleType.NACM_RULE_OPERATION
                        rule.type_data.rpc_names = rule_json.get("rpc-name").split()

                if rule_json.get("notification-name") is not None:
                    if rule.type != NacmRuleType.NACM_RULE_NOTSET:
                        error(
                                "Invalid rule definition (multiple cases from rule-type choice): \"{}\"".format(
                                        rule.name))
                    else:
                        rule.type = NacmRuleType.NACM_RULE_NOTIF
                        rule.type_data.ntf_names = rule_json.get("notification-name").split()

                if rule_json.get("path") is not None:
                    if rule.type != NacmRuleType.NACM_RULE_NOTSET:
                        error(
                                "Invalid rule definition (multiple cases from rule-type choice): \"{}\"".format(
                                        rule.name))
                    else:
                        rule.type = NacmRuleType.NACM_RULE_DATA
                        # i.e. /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ip
                        rule.type_data.path = rule_json["path"]

                rule.action = Action.PERMIT if rule_json["action"] == "permit" else Action.DENY
                rl.rules.append(rule)

            self.rule_lists.append(rl)


# Rules for particular session (logged-in user)
class NacmRpc:
    # "username" only for testing, will be part of "session"
    def __init__(self, config: NacmConfig, data: "BaseDatastore", username: str):
        self.default_read = config.default_read
        self.default_write = config.default_write
        self.default_exec = config.default_exec
        user_groups = list(filter(lambda x: username in x.users, config.nacm_groups))
        user_groups_names = list(map(lambda x: x.name, user_groups))
        self.rule_lists = list(filter(lambda x: (set(user_groups_names) & set(x.groups)), config.rule_lists)) # type: List[NacmRuleList]
        self.config = config
        self.data = data

        for rl in self.rule_lists:
            for rule in rl.rules:
                if not rule.type_data.path:
                    continue

                ii = self.data._dm.parse_instance_id(rule.type_data.path)
                nl = rl.rule_tree
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

    def check_data_node_path(self, ii: InstanceIdentifier, access: Permission) -> Action:
        retval = None
        # nl = self.rule_lists[0].rule_tree
        data_node = self.data.get_data_root()   # type: Instance

        for nl in map(lambda rl: rl.rule_tree, self.rule_lists):
            for isel in ii:
                # node_match = (list(filter(lambda x: x.isel == isel, nl)) or [None])[0]

                # print("j {}".format(isel))
                node_match = None
                for rule_node in nl:
                    if (type(rule_node.isel) == type(isel)) and (rule_node.isel == isel):
                        node_match = rule_node
                        break

                    # print("{} {}".format(type(isel), type(rule_node.isel)))
                    if isinstance(isel, yangson.instance.EntryIndex) and isinstance(rule_node.isel, yangson.instance.EntryKeys):
                        # print("k")
                        if isel.peek_step(data_node.value) is rule_node.isel.peek_step(data_node.value):
                            node_match = rule_node
                            break

                data_node = isel.goto_step(data_node)

                if node_match:
                    retval = node_match.get_action(access)
                    nl = node_match.children
                else:
                    break

        if retval is None:
            # No matching rule
            if access in {Permission.NACM_ACCESS_READ}:
                retval = self.default_read
            else:
                retval = self.default_write

        return retval

    def _check_data_read_path(self, node: Instance, ii: InstanceIdentifier) -> Instance:
        # node = self.data.get_node(ii)

        if isinstance(node.value, ObjectValue):
            # print("obj: {}".format(node.value))
            # print(str(ii))
            for child_key in sorted(node.value.keys()):
                # Do not check leaves
                # if not (isinstance(node.value[child_key], ObjectValue) or isinstance(node.value[child_key], ArrayValue)):
                #     continue

                nsel = yangson.instance.MemberName(child_key)
                m = nsel.goto_step(node)
                mii = copy.copy(ii)
                mii.append(nsel)

                info("checking mii {}".format(mii))
                if self.check_data_node_path(mii, Permission.NACM_ACCESS_READ) == Action.DENY:
                    # info("Pruning node {} {}".format(id(node.value[child_key]), node.value[child_key]))
                    info("Pruning node {}".format(mii))
                    node = node.remove_member(child_key)
                else:
                    node = self._check_data_read_path(m, mii).up()
        elif isinstance(node.value, ArrayValue):
            # print("array: {}".format(node.value))
            i = 0
            arr_len = len(node.value)
            while i < arr_len:
                # Do not check leaves
                # if not (isinstance(node.value[i], ObjectValue) or isinstance(node.value[i], ArrayValue)):
                #     i += 1
                #     continue

                nsel = yangson.instance.EntryIndex(i)
                e = nsel.goto_step(node)
                eii = copy.copy(ii)
                eii.append(yangson.instance.EntryIndex(i))

                info("checking eii {}".format(eii))
                if self.check_data_node_path(eii, Permission.NACM_ACCESS_READ) == Action.DENY:
                    info("Pruning node {} {}".format(id(node.value[i]), node.value[i]))
                    node = node.remove_entry(i)
                    arr_len -= 1
                else:
                    i += 1
                    node = self._check_data_read_path(e, eii).up()


        return node

    def check_data_read_path(self, ii: InstanceIdentifier) -> Instance:
        n = self.data.get_node(ii)
        return self._check_data_read_path(n, ii)

    """
    def check_data_node(self, node: Instance, access: Permission) -> Action:
        if not isinstance(node, Instance):
            raise TypeError("Node not an Instance!")

        i = 0

        print("rule node hashes:")
        for rl in self.rule_lists:
            for rule in rl.rules:
                if rule.type_data.path:
                    try:
                        print("{} {} {}".format(i, rule.name, hash(self.data.get_node_path(rule.type_data.path, PathFormat.XPATH))))
                        i += 1
                    except NonexistentInstance:
                        pass

        n = node
        while not n.is_top():
            #info("checking node {}".format(n.value))

            # try:
            info("checking node {} {}".format(hash(n.value), type(n.value)))

            # except TypeError as e:
            #     info("checking node hash error {}".format(type(n.value)))
            #     info(str(e))
            #     info(n.value)


            for rl in self.rule_lists:
                for rule in rl.rules:
                    debug("Checking rule \"{}\"".format(rule.name))

                    # 1. Module name
                    # TODO Validate against data model
                    debug("- Checking module name")
                    data_model_module_name = rule.module
                    if not (rule.module == "*" or rule.module == data_model_module_name):
                        # rule does not match
                        continue

                    # 3. access - do it before 2 for optimize, the 2nd step is the most difficult
                    debug("- Checking access specifier")
                    if access not in rule.access:
                        # rule does not match
                        continue

                    # 2. type and operation name
                    debug("- Checking type and operation name")
                    if rule.type == NacmRuleType.NACM_RULE_NOTSET:
                        info("Rule found (type notset): {}".format(rule.name))
                        return rule.action

                    if rule.type != NacmRuleType.NACM_RULE_DATA or not rule.type_data.path:
                        continue

                    try:
                        selected = self.data.get_node_path(rule.type_data.path, PathFormat.XPATH)
                        if id(selected.value) == id(n.value):
                            # Success!
                            # the path selects the node
                            info("Rule found: \"{}\"".format(rule.name))
                            return rule.action
                    except NonexistentSchemaNode:
                        warn("Rule error: NonexistentSchemaNode: {}".format(rule.type_data.path))
                    except NonexistentInstance:
                        pass
                        # warn("Rule info - nonexistent node {}".format(rule.type_data.path))

            n = n.up()  # if not n.is_top else None

        # no rule found
        # default action
        info("No rule found, returning default action")

        if access == Permission.NACM_ACCESS_READ:
            return self.default_read
        elif access in (Permission.NACM_ACCESS_CREATE, Permission.NACM_ACCESS_DELETE, Permission.NACM_ACCESS_UPDATE):
            return self.default_write
        else:
            # unknown access request - deny
            return Action.DENY

    def _check_data_read_recursion(self, node: Instance, depth=0) -> Instance:
        if isinstance(node.value, ObjectValue):
            # print("obj: {}".format(node.value))
            for child_key in node.value.keys():
                # Do not check leaves
                if not (
                    isinstance(node.value[child_key], ObjectValue) or isinstance(node.value[child_key], ArrayValue)):
                    continue

                m = node.member(child_key)
                if self.check_data_node(m, Permission.NACM_ACCESS_READ) == Action.DENY:
                    debug("Pruning node {} {}".format(id(node.value[child_key]), node.value[child_key]))
                    node = node.remove_member(child_key)
                    root = node.top()
                else:
                    node = self._check_data_read_recursion(m, depth + 1).up()
        elif isinstance(node.value, ArrayValue):
            # print("array: {}".format(node.value))
            i = 0
            arr_len = len(node.value)
            while i < arr_len:
                # Do not check leaves
                if not (isinstance(node.value[i], ObjectValue) or isinstance(node.value[i], ArrayValue)):
                    i += 1
                    continue

                e = node.entry(i)
                if self.check_data_node(e, Permission.NACM_ACCESS_READ) == Action.DENY:
                    debug("Pruning node {} {}".format(id(node.value[i]), node.value[i]))
                    node = node.remove_entry(i)
                    root = node.top()
                    arr_len -= 1
                else:
                    i += 1
                    node = self._check_data_read_recursion(e, depth + 1).up()

        return node

    def check_data_read(self, node: Instance) -> Instance:
        return self._check_data_read_recursion(node)
    """


def test():
    nacm_data = JsonDatastore("./data", "./data/yang-library-data.json")
    nacm_data.load("jetconf/example-data-nacm.json")

    nacm = NacmConfig(nacm_data)

    data = JsonDatastore("./data", "./data/yang-library-data.json")
    data.load("jetconf/example-data.json")
    data.register_nacm(nacm)

    nrpc = NacmRpc(nacm, data, "dominik")
    ii = nrpc.data._dm.parse_instance_id("/dns-server:dns-server/zones/zone[domain='example.com']")
    act = nrpc.check_data_node_path(ii, Permission.NACM_ACCESS_READ)
    print("\n1 {}".format(act))

    ii2 = nrpc.data._dm.parse_instance_id("/dns-server:dns-server/zones/zone[domain='example.com']/notify")
    act = nrpc.check_data_node_path(ii2, Permission.NACM_ACCESS_READ)
    print("\n2 {}".format(act))

    ii3 = nrpc.data._dm.parse_instance_id("/dns-server:dns-server/zones")
    n = nrpc.check_data_read_path(ii3)
    print("\n3 {}".format(n.value))

    exit()

    test_paths = (
        (
            "/dns-server:dns-server/zones/zone[domain='example.com']/query-module",
            Permission.NACM_ACCESS_UPDATE,
            Action.DENY
        ),
        (
            "/dns-server:dns-server/zones/zone",
            Permission.NACM_ACCESS_READ,
            Action.PERMIT
        )
    )

    for test_path in test_paths:
        info("Testing path \"{}\"".format(test_path[0]))

        datanode = data.get_node_path(test_path[0], PathFormat.XPATH)
        if datanode:
            info("Node found")
            debug("Node contents: {}".format(datanode.value))
            action = nrpc.check_data_node(datanode, test_path[1])
            if action == test_path[2]:
                info("Action = {}, {}\n".format(action.name, "OK"))
            else:
                warn("Action = {}, {}\n".format(action.name, "FAILED"))
        else:
            info("Node not found!")

    _node = data.get_node_path("/dns-server:dns-server/zones/zone[domain='example.com']", PathFormat.XPATH)
    if not _node:
        print("Node null")

    res = nrpc.check_data_read(_node)
    res = json.dumps(res.value, indent=4, sort_keys=True)
    print("result = \n" + res + "\n")

    res_expected = """
    {
    "master": [
        "server1"
    ],
    "access-control-list": [
        "acl-xfr-update",
        "acl-notify"
    ],
    "any-to-tcp": false,
    "template": "default",
    "notify": {
        "recipient": [
            "server0"
        ]
    },
    "domain": "example.com"
    }"""

    if json.loads(res) == json.loads(res_expected):
        info("OK")
    else:
        warn("FAILED")


from .data import JsonDatastore, PathFormat
