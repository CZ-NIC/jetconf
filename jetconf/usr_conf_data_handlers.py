from typing import List, Dict, Union, Any

from yangson.instance import InstanceRoute, ObjectValue, EntryKeys, MemberName
from . import knot_api
from .data import BaseDatastore, SchemaNode, ChangeType, DataChange
from .helpers import PathFormat, ErrorHelpers, LogHelpers, DataHelpers
from .knot_api import RRecordBase, SOARecord, ARecord, AAAARecord, NSRecord, MXRecord
from .handler_list import ConfDataObjectHandler, ConfDataListHandler

JsonNodeT = Union[Dict[str, Any], List]
epretty = ErrorHelpers.epretty
debug_confh = LogHelpers.create_module_dbg_logger(__name__)


# Config handler for "server" section
class KnotConfServerListener(ConfDataObjectHandler):
    def replace(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " replace triggered")

        base_ii = ii[0:2]
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.unset_section(section="server")

        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="comment",
            value=base_nv.get("description")
        )
        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="async-start",
            value=base_nv.get("knot-dns:async-start")
        )
        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="nsid",
            value=base_nv.get("nsid-identity", {}).get("nsid")
        )

        listen_endpoints = base_nv.get("listen-endpoint", [])

        ep_str_list = []
        for ep in listen_endpoints:
            ep_str = ep["ip-address"]
            if ep.get("port"):
                ep_str += "@" + str(ep["port"])
            ep_str_list.append(ep_str)

        knot_api.KNOT.set_item_list(
            section="server",
            identifier=None,
            item="listen",
            value=ep_str_list
        )

        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="rundir",
            value=base_nv.get("filesystem-paths", {}).get("run-time-dir")
        )
        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="pidfile",
            value=base_nv.get("filesystem-paths", {}).get("pid-file")
        )
        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="tcp-workers",
            value=base_nv.get("resources", {}).get("knot-dns:tcp-workers")
        )
        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="udp-workers",
            value=base_nv.get("resources", {}).get("knot-dns:udp-workers")
        )
        knot_api.KNOT.set_item(
            section="server",
            identifier=None,
            item="rate-limit-table-size",
            value=base_nv.get("response-rate-limiting", {}).get("table-size")
        )

    def delete(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " delete triggered")
        knot_api.KNOT.unset_section(section="server")


# Config handler for "log" section
class KnotConfLogListener(ConfDataListHandler):
    def replace_item(self, ii: InstanceRoute, ch: "DataChange"):
        # No big data expected, can rewrite whole list
        self.replace_list(ii, ch)

    def replace_list(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " replace_list triggered")

        base_ii = ii[0:2]
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.unset_section(section="log")

        for logitem in base_nv:
            tgt = logitem.get("target")
            if tgt is None:
                continue

            knot_api.KNOT.set_item(section="log", identifier=None, item="target", value=tgt)
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="comment", value=logitem.get("description"))
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="server", value=logitem.get("server"))
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="zone", value=logitem.get("zone"))
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="any", value=logitem.get("any"))

    def delete_list(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " delete_list triggered")
        knot_api.KNOT.unset_section(section="log")


# Config handler for "zone" section
class KnotConfZoneListener(ConfDataObjectHandler):
    def create(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " create triggered")

        base_ii = ii[0:2]

        # Create new zone
        if (ii == base_ii) and (ch.change_type == ChangeType.CREATE):
            domain = ch.data["zone"]["domain"]
            debug_confh("Creating new zone \"{}\"".format(domain))
            knot_api.KNOT.zone_new(domain)

    def replace(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " replace triggered")

        # Edit particular zone
        if (len(ii) >= 4) and isinstance(ii[2], MemberName) and isinstance(ii[3], EntryKeys):
            domain = ii[3].keys["domain"]
            debug_confh("Editing config of zone \"{}\"".format(domain))

            # Write whole zone config to Knot
            zone_nv = self.ds.get_data_root().goto(ii[0:4]).value
            knot_api.KNOT.unset_section(section="zone", identifier=domain)
            knot_api.KNOT.set_item(
                section="zone",
                identifier=None,
                item="domain",
                value=domain
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="comment",
                value=zone_nv.get("description")
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="file",
                value=zone_nv.get("file")
            )
            knot_api.KNOT.set_item_list(
                section="zone",
                identifier=domain,
                item="master",
                value=zone_nv.get("master", [])
            )
            knot_api.KNOT.set_item_list(
                section="zone",
                identifier=domain,
                item="notify",
                value=zone_nv.get("notify", {}).get("recipient", [])
            )
            knot_api.KNOT.set_item_list(
                section="zone",
                identifier=domain,
                item="acl",
                value=zone_nv.get("access-control-list", [])
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="serial-policy",
                value=zone_nv.get("serial-update-method")
            )

            anytotcp = zone_nv.get("any-to-tcp")
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="disable-any",
                value=str(not anytotcp) if isinstance(anytotcp, bool) else None
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="max-journal-size",
                value=zone_nv.get("journal", {}).get("maximum-journal-size")
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="zonefile-sync",
                value=zone_nv.get("journal", {}).get("zone-file-sync-delay")
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="ixfr-from-differences",
                value=zone_nv.get("journal", {}).get("from-differences")
            )

            qm_list = zone_nv.get("query-module", [])
            knot_api.KNOT.set_item_list(
                section="zone",
                identifier=domain,
                item="module",
                value=list(map(lambda n: n["name"] + "/" + n["type"][0], qm_list))
            )
            knot_api.KNOT.set_item(
                section="zone",
                identifier=domain,
                item="semantic-checks",
                value=zone_nv.get("knot-dns:semantic-checks")
            )

    def delete(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " delete triggered")

        # Delete zone
        if (len(ii) == 4) and isinstance(ii[3], EntryKeys) and (ch.change_type == ChangeType.DELETE):
            domain = ii[3].keys["domain"]
            debug_confh("Deleting zone \"{}\"".format(domain))
            knot_api.KNOT.zone_remove(domain, False)


# Config handler for "control" section
class KnotConfControlListener(ConfDataObjectHandler):
    def replace(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " replace triggered")

        base_ii = ii[0:2]
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.unset_section(section="control")
        knot_api.KNOT.set_item(
            section="control",
            identifier=None,
            item="listen",
            value=base_nv.get("unix")
        )

    def delete(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " delete triggered")
        knot_api.KNOT.unset_section(section="control")


# Config handler for "acl" section
class KnotConfAclListener(ConfDataListHandler):
    @staticmethod
    def _write_list_item(acl_nv: ObjectValue):
        name = acl_nv["name"]
        debug_confh("ACL name={}".format(name))

        knot_api.KNOT.set_item(
            section="acl",
            identifier=None,
            item="id",
            value=name
        )
        knot_api.KNOT.set_item(
            section="acl",
            identifier=name,
            item="comment",
            value=acl_nv.get("description")
        )
        knot_api.KNOT.set_item_list(
            section="acl",
            identifier=name,
            item="key",
            value=acl_nv.get("key", [])
        )
        knot_api.KNOT.set_item_list(
            section="acl",
            identifier=name,
            item="action",
            value=acl_nv.get("operation", [])
        )

        netws = acl_nv.get("network", [])
        knot_api.KNOT.set_item_list(
            section="acl",
            identifier=name,
            item="address",
            value=list(map(lambda n: n["ip-prefix"], netws))
        )

        action = acl_nv.get("action")
        knot_api.KNOT.set_item(
            section="acl",
            identifier=name,
            item="deny",
            value={"deny": "true", "allow": "false"}.get(action)
        )

    def replace_item(self, ii: InstanceRoute, ch: "DataChange"):
        debug_confh(self.__class__.__name__ + " replace triggered")

        base_ii = ii[0:3]   # type: InstanceRoute
        base_nv = self.ds.get_data_root().goto(base_ii).value   # type: ObjectValue

        acl_name = base_nv["name"]
        knot_api.KNOT.unset_section(section="acl", identifier=acl_name)
        self._write_list_item(base_nv)

    def replace_list(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " replace triggered")

        base_ii = ii[0:2]
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.unset_section(section="acl")
        for acl_nv in base_nv:
            self._write_list_item(acl_nv)

    def delete_list(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " delete triggered")
        knot_api.KNOT.unset_section(section="acl")


class RRHelpers:
    # Create RR object from "rdata" json node
    @staticmethod
    def rr_from_rdata_item(domain_name: str, rr_owner: str, rr_ttl: int, rr_type: str, rdata_item: JsonNodeT) -> RRecordBase:
        try:
            if rr_type == "A":
                new_rr = ARecord(domain_name, rr_ttl)
                new_rr.owner = rr_owner
                new_rr.address = rdata_item["A"]["address"]
            elif rr_type == "AAAA":
                new_rr = AAAARecord(domain_name, rr_ttl)
                new_rr.owner = rr_owner
                new_rr.address = rdata_item["AAAA"]["address"]
            elif rr_type == "NS":
                new_rr = NSRecord(domain_name, rr_ttl)
                new_rr.owner = rr_owner
                new_rr.nsdname = rdata_item["NS"]["nsdname"]
            elif rr_type == "MX":
                new_rr = MXRecord(domain_name, rr_ttl)
                new_rr.owner = rr_owner
                new_rr.exchange = rdata_item["MX"]["exchange"]
            else:
                new_rr = None
        except KeyError:
            new_rr = None

        return new_rr


# Zone data handler
class KnotZoneDataListener(ConfDataObjectHandler):
    def process(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        domain_name = ii[2].keys["name"]

        base_ii = ii[0:3]
        base_data = self.ds.get_data_root().goto(base_ii).value

        # Remove the whole zone from Knot
        knot_api.KNOT.zone_remove(domain_name, purge_data=True)

        # Create new zone with SOA in zone data section
        def_ttl = base_data["default-ttl"]

        soa = base_data.get("zone", {}).get("SOA")

        soarr = SOARecord()
        soarr.ttl = def_ttl
        soarr.mname = soa["mname"]
        soarr.rname = soa["rname"]
        soarr.serial = soa["serial"]
        soarr.refresh = soa["refresh"]
        soarr.retry = soa["retry"]
        soarr.expire = soa["expire"]
        soarr.minimum = soa["minimum"]

        debug_confh("KnotApi: adding new SOA RR to zone \"{}\"".format(domain_name))
        knot_api.KNOT.zone_add_record(domain_name, soarr)

        for rr in base_data.get("rrset", []):
            # Add resource record to particular zone
            rr_owner = rr["owner"]
            rr_type = rr.get("type").split(":")[-1]
            rr_ttl = rr.get("ttl")
            if rr_ttl is None:
                # Obtain default ttl from datastore if not specified explicitly
                rr_ttl = base_data["default-ttl"]

            for rdata_item in rr["rdata"]:
                new_rr = RRHelpers.rr_from_rdata_item(domain_name, rr_owner, rr_ttl, rr_type, rdata_item)
                if new_rr is not None:
                    debug_confh("KnotApi: adding new {} RR to zone \"{}\"".format(rr_type, domain_name))
                    knot_api.KNOT.zone_add_record(domain_name, new_rr)


class KnotZoneDataRRListener(ConfDataObjectHandler):
    def process(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        domain_name = ii[2].keys["name"]
        rr_owner = ii[4].keys["owner"]
        rr_type = ii[4].keys["type"][0]

        base_ii = ii[0:5]
        base_data_persistent = self.ds.get_data_root().goto(base_ii)
        base_data = base_data_persistent.value

        # Delete resource record from particular zone
        debug_confh("KnotApi: deleting {} RR from zone \"{}\"".format(rr_type, domain_name))
        knot_api.KNOT.zone_del_record(domain_name, rr_owner, rr_type)

        # Write new resource record(s)
        for rdata_item in base_data["rdata"]:
            rr_ttl = base_data.get("ttl")
            if rr_ttl is None:
                # Obtain default ttl from datastore if not specified explicitly
                rr_ttl = base_data_persistent.up().value["default-ttl"]

            new_rr = RRHelpers.rr_from_rdata_item(domain_name, rr_owner, rr_ttl, rr_type, rdata_item)
            if new_rr is not None:
                debug_confh("KnotApi: adding new {} RR to zone \"{}\"".format(rr_type, domain_name))
                knot_api.KNOT.zone_add_record(domain_name, new_rr)


class KnotZoneDataRdataListener(ConfDataObjectHandler):
    def process(self, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        domain_name = ii[2].keys["name"]
        rr_owner = ii[4].keys["owner"]
        rr_type = ii[4].keys["type"][0]

        base_ii = ii[0:7]
        base_data_persistent = self.ds.get_data_root().goto(base_ii)
        base_data = base_data_persistent.value

        # Delete resource record from particular zone
        rr_sel = RRHelpers.rr_from_rdata_item(domain_name, rr_owner, 0, rr_type, base_data)
        debug_confh("KnotApi: deleting {} RR from zone \"{}\"".format(rr_type, domain_name))
        knot_api.KNOT.zone_del_record(domain_name, rr_owner, rr_type, selector=rr_sel.rrdata_format())

        # Write new resource record
        rr_ttl = base_data_persistent.up().value.get("ttl")
        if rr_ttl is None:
            # Obtain default ttl from datastore if not specified explicitly
            rr_ttl = base_data_persistent.up().up().value["default-ttl"]

        new_rr = RRHelpers.rr_from_rdata_item(domain_name, rr_owner, rr_ttl, rr_type, base_data)
        if new_rr is not None:
            debug_confh("KnotApi: adding new {} RR to zone \"{}\"".format(rr_type, domain_name))
            knot_api.KNOT.zone_add_record(domain_name, new_rr)
