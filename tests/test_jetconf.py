import json
import pytest
from jetconf.helpers import DataHelpers
from jetconf.data import JsonDatastore, RpcInfo, PathFormat
from jetconf.nacm import NacmConfig, Permission, Action


@pytest.fixture
def data_model():
    return DataHelpers.load_data_model("./data", "./data/yang-library-data.json")


@pytest.fixture
def datastore_1(data_model):
    ds = JsonDatastore(data_model)
    ds.load("jetconf/example-data.json")
    return ds


@pytest.fixture
def nacm_datastore_1(data_model):
    ds = JsonDatastore(data_model)
    ds.load("jetconf/example-data-nacm.json")
    return ds


def test_datastore(datastore_1):
    data = datastore_1
    rpc = RpcInfo()
    rpc.username = "dominik"
    rpc.path = "/dns-server:dns-server/zones/zone[domain='example.com']/query-module"
    rpc.path_format = PathFormat.XPATH

    # info("Testing read of " + rpc.path)
    n = data.get_node_rpc(rpc)

    expected_value = \
        [
            {'name': 'test1', 'type': 'knot-dns:synth-record'},
            {'name': 'test2', 'type': 'knot-dns:synth-record'}
        ]

    assert json.loads(json.dumps(n.value)) == expected_value

    rpc.path = "/dns-server:dns-server/zones"
    rpc.path_format = PathFormat.URL

    # info("Testing creation of new list item (zone myzone.com) in " + rpc.path)
    new_root = data.create_node_rpc(data.get_data_root(), rpc, {"zone": {"domain": "myzone.com"}})
    new_node_ii = data.parse_ii("/dns-server:dns-server/zones/zone", PathFormat.URL)
    new_node = new_root.goto(new_node_ii)
    assert "myzone.com" in map(lambda x: x.get("domain"), new_node.value)

    rpc.path = "/dns-server:dns-server/zones/zone=myzone.com"
    rpc.path_format = PathFormat.URL

    # info("Testing creation of new leaf-list inside object " + rpc.path)
    new_root2 = data.create_node_rpc(new_root, rpc, {"access-control-list": "acl-notify-pokus"})
    new_node_ii = data.parse_ii("/dns-server:dns-server/zones/zone=myzone.com", PathFormat.URL)
    new_node2 = new_root2.goto(new_node_ii)
    assert "acl-notify-pokus" in new_node2.member("access-control-list").value


def test_nacm(datastore_1, nacm_datastore_1):
    nacm_data = nacm_datastore_1
    nacm_conf = NacmConfig(nacm_data)

    data = datastore_1
    data.register_nacm(nacm_conf)
    nacm_conf.set_ds(data)

    test_user = "dominik"

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
            Action.PERMIT
        )
    )

    for test_path in test_paths:
        print("Testing path \"{}\"".format(test_path[0]))

        ii = data.parse_ii(test_path[0], PathFormat.XPATH)
        datanode = data.get_node(data.get_data_root(), ii)
        if datanode:
            print("Node found")
            # debug("Node contents: {}".format(datanode.value))
            test_ii = data.parse_ii(test_path[0], PathFormat.XPATH)
            rule = []
            action = nacm_conf.get_user_rules(test_user).check_data_node_permission(data.get_data_root(), test_ii, test_path[1],
                                                                                    out_matching_rule=rule)
            assert action == test_path[2]
            """
            if action == test_path[2]:
                info("Action = {}, OK ({})\n".format(action.name, rule[0].name if len(rule) > 0 else "default"))
            else:
                info("Action = {}, FAILED ({})\n".format(action.name, rule[0].name if len(rule) > 0 else "default"))
            """
        else:
            pytest.fail("Node not found!")

    test_ii2 = data.parse_ii("/dns-server:dns-server/zones/zone[domain='example.com']", PathFormat.XPATH)

    # info("Reading: " + str(test_ii2))
    res = nacm_conf.get_user_rules(test_user).prun_data_tree(data.get_data_root(), test_ii2)
    res = json.dumps(res.value, indent=4, sort_keys=True)

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

    assert json.loads(res) == json.loads(res_expected)
