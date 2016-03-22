import json
import collections
import copy
from threading import Lock
from enum import Enum
from colorlog import error, warning as warn, info, debug
from typing import List, Set

from yangson.instance import \
    Instance, \
    NonexistentInstance, \
    ArrayValue, \
    ObjectValue, \
    InstanceSelector, \
    InstanceIdentifier, \
    MemberName, \
    EntryIndex, \
    EntryKeys


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
        self.rule_tree = []     # type: List[RuleTreeNode]

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
        self.internal_data_lock = Lock()
        self._lock_username = None

        try:
            self.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm")
        except NonexistentInstance:
            raise ValueError("Data does not contain \"ietf-netconf-acm:nacm\" root element")

        self.update()

    # Fills internal read-only data structures
    def update(self):
        lock_res = self.internal_data_lock.acquire(blocking=True, timeout=1)
        if not lock_res:
            error("NACM update: cannot acquire data lock")
            return

        self.nacm_groups = []
        self.rule_lists = []

        nacm_json = self.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm").value
        self.enabled = nacm_json["enable-nacm"]

        # NACM not enabled, no need to continue
        if not self.enabled:
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
                        # i.e. /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ip
                        rule.type_data.path = rule_json["path"]

                rule.action = Action.PERMIT if rule_json["action"] == "permit" else Action.DENY
                rl.rules.append(rule)

            self.rule_lists.append(rl)

        self.internal_data_lock.release()


# Rules for particular session (logged-in user)
class NacmRpc:
    # "username" only for testing, will be part of "session"
    def __init__(self, config: NacmConfig, data: "BaseDatastore", username: str):
        self.nacm_enabled = config.enabled
        # self.config = config
        self.data = data
        self.default_read = Action.DENY
        self.default_write = Action.DENY
        self.default_exec = Action.DENY
        self.rule_lists = []

        if not self.nacm_enabled:
            return

        lock_res = config.internal_data_lock.acquire(blocking=True, timeout=1)
        if not lock_res:
            error("NacmRpc: cannot acquire config lock ")
            return

        self.default_read = config.default_read
        self.default_write = config.default_write
        self.default_exec = config.default_exec
        user_groups = list(filter(lambda x: username in x.users, config.nacm_groups))
        user_groups_names = list(map(lambda x: x.name, user_groups))
        self.rule_lists = list(filter(lambda x: (set(user_groups_names) & set(x.groups)), config.rule_lists))

        # No need to hold lock anymore
        # config.update() always creates new structures instead of modifying ones
        config.internal_data_lock.release()

        for rl in self.rule_lists:
            for rule in rl.rules:
                if not rule.type_data.path:
                    continue

                ii = self.data.parse_ii(rule.type_data.path, PathFormat.XPATH)
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

    def check_data_node_path(self, ii: InstanceIdentifier, access: Permission, out_matching_rule: List[NacmRule]=None) -> Action:
        if not self.nacm_enabled:
            return Action.PERMIT

        retval = None
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
                    if isinstance(isel, EntryIndex) and isinstance(rule_node.isel, EntryKeys):
                        # print("k")
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

                nsel = MemberName(child_key)
                m = nsel.goto_step(node)
                mii = copy.copy(ii)
                mii.append(nsel)

                debug("checking mii {}".format(mii))
                if self.check_data_node_path(mii, Permission.NACM_ACCESS_READ) == Action.DENY:
                    # info("Pruning node {} {}".format(id(node.value[child_key]), node.value[child_key]))
                    debug("Pruning node {}".format(mii))
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

                nsel = EntryIndex(i)
                e = nsel.goto_step(node)
                eii = copy.copy(ii)
                eii.append(nsel)

                debug("checking eii {}".format(eii))
                if self.check_data_node_path(eii, Permission.NACM_ACCESS_READ) == Action.DENY:
                    debug("Pruning node {} {}".format(id(node.value[i]), node.value[i]))
                    node = node.remove_entry(i)
                    arr_len -= 1
                else:
                    i += 1
                    node = self._check_data_read_path(e, eii).up()

        return node

    def check_data_read_path(self, ii: InstanceIdentifier) -> Instance:
        n = self.data.get_node(ii)
        if not self.nacm_enabled:
            return n
        else:
            return self._check_data_read_path(n, ii)


def test():
    nacm_data = JsonDatastore("./data", "./data/yang-library-data.json")
    nacm_data.load("jetconf/example-data-nacm.json")

    nacm = NacmConfig(nacm_data)

    data = JsonDatastore("./data", "./data/yang-library-data.json")
    data.load("jetconf/example-data.json")
    data.register_nacm(nacm)

    nrpc = NacmRpc(nacm, data, "dominik")

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
        ),
        (
            "/dns-server:dns-server/server-options",
            Permission.NACM_ACCESS_READ,
            Action.DENY
        )
    )

    for test_path in test_paths:
        info("Testing path \"{}\"".format(test_path[0]))

        datanode = data.get_node_path(test_path[0], PathFormat.XPATH)
        if datanode:
            info("Node found")
            debug("Node contents: {}".format(datanode.value))
            test_ii = data.parse_ii(test_path[0], PathFormat.XPATH)
            rule = []
            action = nrpc.check_data_node_path(test_ii, test_path[1], out_matching_rule=rule)
            if action == test_path[2]:
                info("Action = {}, OK ({})\n".format(action.name, rule[0].name if len(rule) > 0 else "default"))
            else:
                info("Action = {}, FAILED ({})\n".format(action.name, rule[0].name if len(rule) > 0 else "default"))
        else:
            info("Node not found!")

    test_ii2 = data.parse_ii("/dns-server:dns-server/zones/zone[domain='example.com']", PathFormat.XPATH)

    info("Reading: " + str(test_ii2))
    res = nrpc.check_data_read_path(test_ii2)
    res = json.dumps(res.value, indent=4, sort_keys=True)
    print("Result =")
    print(res)

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
