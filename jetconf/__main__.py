import colorlog
import getopt
import logging
import sys

from colorlog import info, warning as warn
from importlib import import_module
from yangson.instance import InstancePath, NonexistentInstance, ObjectValue, EntryKeys
from . import usr_op_handlers, usr_state_data_handlers
from .rest_server import RestServer
from .config import CONFIG, load_config, print_config
from .nacm import NacmConfig
from .data import JsonDatastore, BaseDataListener, SchemaNode, PathFormat, ChangeType, DataChange
from .helpers import DataHelpers
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES
from .knot_api import KNOT, KnotConfig, SOARecord


def knot_connect():
    info("Connecting to KNOT socket")
    KNOT.knot_connect()


def knot_disconnect():
    info("Disonnecting from KNOT socket")
    KNOT.knot_disconnect()


class KnotConfServerListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstancePath, ch: DataChange):
        print("Change at sn \"{}\", dn \"{}\"".format(sn.name, ii))

        base_ii_str = self.schema_path
        base_ii = self._ds.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self._ds.get_node(self._ds.get_data_root(), base_ii).value

        KNOT.begin()

        KNOT.set_item(section="server", item="comment", data=base_nv.get("description"))
        KNOT.set_item(section="server", item="async-start", data=base_nv.get("knot-dns:async-start"))
        KNOT.set_item(section="server", item="nsid", data=base_nv.get("nsid-identity", {}).get("nsid"))

        listen_endpoints = base_nv.get("listen-endpoint") or []

        ep_str_list = []
        for ep in listen_endpoints:
            ep_str = ep["ip-address"]
            if ep.get("port"):
                ep_str += "@" + str(ep["port"])
            ep_str_list.append(ep_str)
        KNOT.set_item_list(section="server", item="listen", data=ep_str_list)

        KNOT.set_item(section="server", item="rundir", data=base_nv.get("filesystem-paths", {}).get("run-time-dir"))
        KNOT.set_item(section="server", item="pidfile", data=base_nv.get("filesystem-paths", {}).get("pid-file"))
        KNOT.set_item(section="server", item="tcp-workers", data=base_nv.get("resources", {}).get("knot-dns:tcp-workers"))
        KNOT.set_item(section="server", item="udp-workers", data=base_nv.get("resources", {}).get("knot-dns:udp-workers"))
        KNOT.set_item(section="server", item="rate-limit-table-size", data=base_nv.get("response-rate-limiting", {}).get("table-size"))

        KNOT.commit()


class KnotConfLogListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstancePath, ch: DataChange):
        print("lChange at sn \"{}\", dn \"{}\"".format(sn.name, ii))
        base_ii_str = self.schema_path
        base_ii = self._ds.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self._ds.get_node(self._ds.get_data_root(), base_ii).value

        KNOT.begin()
        KNOT.set_item(section="log", data=None)

        for logitem in base_nv:
            tgt = logitem.get("target")
            if tgt is None:
                continue

            KNOT.set_item(section="log", item="target", data=tgt)
            KNOT.set_item(section="log", identifier=tgt, item="comment", data=logitem.get("description"))
            KNOT.set_item(section="log", identifier=tgt, item="server", data=logitem.get("server"))
            KNOT.set_item(section="log", identifier=tgt, item="zone", data=logitem.get("zone"))
            KNOT.set_item(section="log", identifier=tgt, item="any", data=logitem.get("any"))

        KNOT.commit()


class KnotConfZoneListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstancePath, ch: DataChange):
        print("zChange at sn \"{}\", dn \"{}\"".format(sn.name, ii))
        base_ii_str = self.schema_path
        base_ii = self._ds.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self._ds.get_node(self._ds.get_data_root(), base_ii).value

        zone_nv = self._ds.get_node(self._ds.get_data_root(), ii[0:(len(base_ii) + 1)]).value
        print("zone nv={}".format(zone_nv))
        nv = self._ds.get_node(self._ds.get_data_root(), ii).value

        # zone_name = tuple(ii[len(base_ii)].keys.values())[0]

        KNOT.begin()

        domain = zone_nv.get("domain")
        KNOT.set_item(section="zone", zone=domain, data=None)
        KNOT.set_item(section="zone", item="domain", data=domain)

        print("zn={}".format(domain))

        KNOT.set_item(section="zone", zone=domain, item="comment", data=zone_nv.get("description"))
        KNOT.set_item(section="zone", zone=domain, item="file", data=zone_nv.get("file"))
        KNOT.set_item_list(section="zone", zone=domain, item="master", data=zone_nv.get("master"))
        KNOT.set_item_list(section="zone", zone=domain, item="notify", data=zone_nv.get("notify", {}).get("recipient"))
        KNOT.set_item_list(section="zone", zone=domain, item="acl", data=zone_nv.get("access-control-list"))
        KNOT.set_item(section="zone", zone=domain, item="serial-policy", data=zone_nv.get("serial-update-method"))

        anytotcp = zone_nv.get("any-to-tcp")
        disable_any_str = str(not anytotcp) if isinstance(anytotcp, bool) else None
        KNOT.set_item(section="zone", zone=domain, item="disable-any", data=disable_any_str)

        KNOT.set_item(section="zone", zone=domain, item="max-journal-size", data=zone_nv.get("journal", {}).get("maximum-journal-size"))
        KNOT.set_item(section="zone", zone=domain, item="zonefile-sync", data=zone_nv.get("journal", {}).get("zone-file-sync-delay"))
        KNOT.set_item(section="zone", zone=domain, item="ixfr-from-differences", data=zone_nv.get("journal", {}).get("from-differences"))

        qms = zone_nv.get("query-module")
        if qms is not None:
            qm_str_list = list(map(lambda n: n["name"] + "/" + n["type"], qms))
        else:
            qm_str_list = None
        KNOT.set_item_list(section="zone", zone=domain, item="module", data=qm_str_list)

        # dnssec-signing:dnssec-signing ?

        KNOT.set_item(section="zone", zone=domain, item="semantic-checks", data=zone_nv.get("knot-dns:semantic-checks"))

        KNOT.commit()


class KnotConfControlListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstancePath, ch: DataChange):
        print("cChange at sn \"{}\", dn \"{}\"".format(sn.name, ii))

        base_ii_str = self.schema_path
        base_ii = self._ds.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self._ds.get_node(self._ds.get_data_root(), base_ii).value

        KNOT.begin()
        KNOT.set_item(section="control", item="listen", data=base_nv.get("unix"))
        KNOT.commit()


class KnotConfAclListener(BaseDataListener):
    def _process_list_item(self, acl_nv: ObjectValue):
        name = acl_nv.get("name")
        print("name={}".format(name))
        KNOT.set_item(section="acl", identifier=name, data=None)
        KNOT.set_item(section="acl", item="id", data=name)
        KNOT.set_item(section="acl", identifier=name, item="comment", data=acl_nv.get("description"))
        KNOT.set_item_list(section="acl", identifier=name, item="key", data=acl_nv.get("key"))
        KNOT.set_item_list(section="acl", identifier=name, item="action", data=acl_nv.get("operation"))

        netws = acl_nv.get("network")
        if netws is not None:
            addrs = list(map(lambda n: n["ip-prefix"], netws))
            KNOT.set_item_list(section="acl", identifier=name, item="address", data=addrs)

        action = acl_nv.get("action")
        deny = "true" if action == "deny" else "false"
        KNOT.set_item(section="acl", identifier=name, item="deny", data=deny)

    def process(self, sn: SchemaNode, ii: InstancePath, ch: DataChange):
        base_ii_str = self.schema_path
        print("aChange at sn \"{}\", dn \"{}\"".format(sn.name, ii))
        base_ii = self._ds.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self._ds.get_node(self._ds.get_data_root(), base_ii).value

        KNOT.begin()
        KNOT.set_item(section="acl", data=None)

        if (len(ii) > len(base_ii)) and isinstance(ii[len(base_ii)], EntryKeys):
            # Write only changed list item
            acl_nv = self._ds.get_node(self._ds.get_data_root(), ii[0:(len(base_ii) + 1)]).value
            print("acl nv={}".format(acl_nv))
            self._process_list_item(acl_nv)
        else:
            # Delete all list items from KNOT
            KNOT.set_item(section="acl", data=None)
            # Write whole list
            for acl_nv in base_nv:
                print("acl nv={}".format(acl_nv))
                self._process_list_item(acl_nv)

        KNOT.commit()


class KnotZoneDataListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstancePath, ch: DataChange):
        base_ii_str = self.schema_path
        print("zdChange at sn \"{}\", dn \"{}\"".format(sn.name, ii))
        base_ii = self._ds.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self._ds.get_node(self._ds.get_data_root(), base_ii).value

        if (ii == base_ii) and (ch.change_type == ChangeType.CREATE):
            name = ch.data["zone"]["name"]
            print("--- Creating new zone \"{}\"".format(name))
            KNOT.begin()
            KNOT.set_item(section="zone", item="domain", data=name)
            KNOT.commit()
        elif (len(ii) == (len(base_ii) + 2)) and isinstance(ii[len(base_ii) + 1], EntryKeys) and (ch.change_type == ChangeType.DELETE):
            name = ii[len(base_ii) + 1].keys["name"]
            print("--- Deleting zone \"{}\"".format(name))
            KNOT.begin()
            KNOT.zone_new(name)
            KNOT.commit()
        elif (len(ii) > len(base_ii)) and isinstance(ii[len(base_ii) + 1], EntryKeys):
            zone_name = ii[len(base_ii) + 1].keys["name"]
            print("--- Zone \"{}\" resource {}".format(zone_name, ch.change_type.name.lower()))
            if ch.change_type == ChangeType.CREATE:
                soa = ch.data.get("SOA")
                if soa is not None:
                    print("writing soa {}".format(soa))
                    KNOT.begin_zone()
                    soarr = SOARecord(zone_name)
                    soarr.mname = soa["mname"]
                    soarr.rname = soa["rname"]
                    soarr.serial = soa["serial"]
                    soarr.refresh = soa["refresh"]
                    soarr.retry = soa["retry"]
                    soarr.expire = soa["expire"]
                    soarr.minimum = soa["minimum"]
                    KNOT.zone_add_record(zone_name, soarr)
                    KNOT.commit_zone()


def main():
    # Load configuration
    load_config("jetconf/config.yaml")
    print_config()

    # Load data model
    datamodel = DataHelpers.load_data_model("data/", "data/yang-library-data.json")

    # NACM init
    nacm_datastore = JsonDatastore(datamodel, "NACM data")
    nacm_datastore.load("jetconf/example-data-nacm.json")

    nacmc = NacmConfig(nacm_datastore)

    # Datastore init
    datastore = JsonDatastore(datamodel, "DNS data")
    datastore.load("jetconf/example-data.json")
    datastore.register_nacm(nacmc)
    nacmc.set_ds(datastore)

    # Register schema listeners
    # We need to hold references somewhere
    sch_lo = []
    sch_lo.append(KnotConfServerListener(datastore, "/dns-server:dns-server/server-options"))
    sch_lo.append(KnotConfLogListener(datastore, "/dns-server:dns-server/knot-dns:log"))
    sch_lo.append(KnotConfZoneListener(datastore, "/dns-server:dns-server/zones/zone"))
    sch_lo.append(KnotConfControlListener(datastore, "/dns-server:dns-server/knot-dns:control-socket"))
    sch_lo.append(KnotConfAclListener(datastore, "/dns-server:dns-server/access-control-list"))
    sch_lo.append(KnotZoneDataListener(datastore, "/dns-zones:zones"))

    # Register op handlers
    OP_HANDLERS.register_handler("generate-key", usr_op_handlers.sign_op_handler)

    # Create and register state data handlers
    usr_state_data_handlers.create_zone_state_handlers(STATE_DATA_HANDLES, datamodel)

    # Initialize Knot control interface
    global KNOT
    KNOT = KnotConfig(CONFIG["KNOT"]["SOCKET"])
    datastore.commit_begin_callback = knot_connect
    datastore.commit_end_callback = knot_disconnect

    # Create HTTP server
    rest_srv = RestServer()
    rest_srv.register_api_handlers(datastore)
    rest_srv.register_static_handlers()

    # Run HTTP server
    rest_srv.run()


if __name__ == "__main__":
    opts, args = (None, None)

    colorlog.basicConfig(
        format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(message)s",
        level=logging.INFO,
        stream=sys.stdout
    )

    test_module = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:")
    except getopt.GetoptError:
        print("Invalid argument detected. Possibles are: -t (test module)")
        exit()

    for opt, arg in opts:
        if opt == '-t':
            test_module = arg

    if test_module is not None:
        try:
            tm = import_module("." + test_module, "jetconf")
            tm.test()
        except ImportError as e:
            print(e.msg)

    else:
        main()
