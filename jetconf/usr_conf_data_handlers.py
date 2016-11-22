from colorlog import info, warning as warn, error
from typing import List, Dict, Union, Any

from yangson.instance import InstanceRoute, ObjectValue, EntryKeys, MemberName
from . import knot_api
from .data import BaseDataListener, SchemaNode, ChangeType, DataChange, ConfHandlerResult
from .helpers import PathFormat, ErrorHelpers, LogHelpers, DataHelpers
from .knot_api import RRecordBase, SOARecord, ARecord, AAAARecord, NSRecord, MXRecord

JsonNodeT = Union[Dict[str, Any], List]
epretty = ErrorHelpers.epretty
debug_confh = LogHelpers.create_module_dbg_logger(__name__)


class KnotConfServerListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        base_ii_str = self.schema_path
        base_ii = DataHelpers.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.set_item(section="server", item="comment", data=base_nv.get("description"))
        knot_api.KNOT.set_item(section="server", item="async-start", data=base_nv.get("knot-dns:async-start"))
        knot_api.KNOT.set_item(section="server", item="nsid", data=base_nv.get("nsid-identity", {}).get("nsid"))

        listen_endpoints = base_nv.get("listen-endpoint", [])

        ep_str_list = []
        for ep in listen_endpoints:
            ep_str = ep["ip-address"]
            if ep.get("port"):
                ep_str += "@" + str(ep["port"])
            ep_str_list.append(ep_str)
        knot_api.KNOT.set_item_list(section="server", item="listen", data=ep_str_list)

        knot_api.KNOT.set_item(section="server", item="rundir", data=base_nv.get("filesystem-paths", {}).get("run-time-dir"))
        knot_api.KNOT.set_item(section="server", item="pidfile", data=base_nv.get("filesystem-paths", {}).get("pid-file"))
        knot_api.KNOT.set_item(section="server", item="tcp-workers", data=base_nv.get("resources", {}).get("knot-dns:tcp-workers"))
        knot_api.KNOT.set_item(section="server", item="udp-workers", data=base_nv.get("resources", {}).get("knot-dns:udp-workers"))
        knot_api.KNOT.set_item(section="server", item="rate-limit-table-size", data=base_nv.get("response-rate-limiting", {}).get("table-size"))

        return ConfHandlerResult.OK


class KnotConfLogListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        base_ii_str = self.schema_path
        base_ii = DataHelpers.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.set_item(section="log", data=None)

        for logitem in base_nv:
            tgt = logitem.get("target")
            if tgt is None:
                continue

            knot_api.KNOT.set_item(section="log", item="target", data=tgt)
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="comment", data=logitem.get("description"))
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="server", data=logitem.get("server"))
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="zone", data=logitem.get("zone"))
            knot_api.KNOT.set_item(section="log", identifier=tgt, item="any", data=logitem.get("any"))

        return ConfHandlerResult.OK


class KnotConfZoneListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        # ii_str = "".join([str(seg) for seg in ii])
        base_ii_str = self.schema_path
        base_ii = DataHelpers.parse_ii(base_ii_str, PathFormat.URL)

        # Create new zone
        if (ii == base_ii) and (ch.change_type == ChangeType.CREATE):
            domain = ch.data["zone"]["domain"]
            debug_confh("Creating new zone \"{}\"".format(domain))
            knot_api.KNOT.zone_new(domain)
        # Delete zone
        elif (len(ii) == (len(base_ii) + 2)) and isinstance(ii[len(base_ii) + 1], EntryKeys) and (ch.change_type == ChangeType.DELETE):
            domain = ii[len(base_ii) + 1].keys["domain"]
            debug_confh("Deleting zone \"{}\"".format(domain))
            knot_api.KNOT.zone_remove(domain)
        # Edit particular zone
        elif (len(ii) >= (len(base_ii) + 2)) and isinstance(ii[len(base_ii)], MemberName) and isinstance(ii[len(base_ii) + 1], EntryKeys):
            domain = ii[len(base_ii) + 1].keys["domain"]
            debug_confh("Editing config of zone \"{}\"".format(domain))

            # Write whole zone config to Knot
            zone_nv = self.ds.get_data_root().goto(ii[0:(len(base_ii) + 1)]).value
            knot_api.KNOT.set_item(section="zone", zone=domain, item="comment", data=zone_nv.get("description"))
            knot_api.KNOT.set_item(section="zone", zone=domain, item="file", data=zone_nv.get("file"))
            knot_api.KNOT.set_item_list(section="zone", zone=domain, item="master", data=zone_nv.get("master"))
            knot_api.KNOT.set_item_list(section="zone", zone=domain, item="notify", data=zone_nv.get("notify", {}).get("recipient"))
            knot_api.KNOT.set_item_list(section="zone", zone=domain, item="acl", data=zone_nv.get("access-control-list"))
            knot_api.KNOT.set_item(section="zone", zone=domain, item="serial-policy", data=zone_nv.get("serial-update-method"))

            anytotcp = zone_nv.get("any-to-tcp")
            disable_any_str = str(not anytotcp) if isinstance(anytotcp, bool) else None
            knot_api.KNOT.set_item(section="zone", zone=domain, item="disable-any", data=disable_any_str)

            knot_api.KNOT.set_item(section="zone", zone=domain, item="max-journal-size", data=zone_nv.get("journal", {}).get("maximum-journal-size"))
            knot_api.KNOT.set_item(section="zone", zone=domain, item="zonefile-sync", data=zone_nv.get("journal", {}).get("zone-file-sync-delay"))
            knot_api.KNOT.set_item(section="zone", zone=domain, item="ixfr-from-differences", data=zone_nv.get("journal", {}).get("from-differences"))

            qms = zone_nv.get("query-module")
            if qms is not None:
                qm_str_list = list(map(lambda n: n["name"] + "/" + n["type"], qms))
            else:
                qm_str_list = None
            knot_api.KNOT.set_item_list(section="zone", zone=domain, item="module", data=qm_str_list)
            knot_api.KNOT.set_item(section="zone", zone=domain, item="semantic-checks", data=zone_nv.get("knot-dns:semantic-checks"))

        return ConfHandlerResult.OK


class KnotConfControlListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        base_ii_str = self.schema_path
        base_ii = DataHelpers.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.set_item(section="control", item="listen", data=base_nv.get("unix"))
        return ConfHandlerResult.OK


class KnotConfAclListener(BaseDataListener):
    def _process_list_item(self, acl_nv: ObjectValue):
        name = acl_nv.get("name")
        debug_confh("ACL name={}".format(name))
        knot_api.KNOT.set_item(section="acl", identifier=name, data=None)
        knot_api.KNOT.set_item(section="acl", item="id", data=name)
        knot_api.KNOT.set_item(section="acl", identifier=name, item="comment", data=acl_nv.get("description"))
        knot_api.KNOT.set_item_list(section="acl", identifier=name, item="key", data=acl_nv.get("key"))
        knot_api.KNOT.set_item_list(section="acl", identifier=name, item="action", data=acl_nv.get("operation"))

        netws = acl_nv.get("network")
        if netws is not None:
            addrs = list(map(lambda n: n["ip-prefix"], netws))
            knot_api.KNOT.set_item_list(section="acl", identifier=name, item="address", data=addrs)

        action = acl_nv.get("action")
        deny = "true" if action == "deny" else "false"
        knot_api.KNOT.set_item(section="acl", identifier=name, item="deny", data=deny)

    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        base_ii_str = self.schema_path
        base_ii = DataHelpers.parse_ii(base_ii_str, PathFormat.URL)
        base_nv = self.ds.get_data_root().goto(base_ii).value

        knot_api.KNOT.set_item(section="acl", data=None)

        if (len(ii) > len(base_ii)) and isinstance(ii[len(base_ii)], EntryKeys):
            # Write only changed list item
            acl_nv = self.ds.get_data_root().goto(ii[0:(len(base_ii) + 1)]).value
            print("acl nv={}".format(acl_nv))
            self._process_list_item(acl_nv)
        else:
            # Delete all list items from KNOT
            knot_api.KNOT.set_item(section="acl", data=None)
            # Write whole list
            for acl_nv in base_nv:
                print("acl nv={}".format(acl_nv))
                self._process_list_item(acl_nv)

        return ConfHandlerResult.OK


class KnotZoneDataListener(BaseDataListener):
    # Create RR object from "rdata" json node
    @staticmethod
    def _rr_from_rdata_item(domain_name: str, rr_owner: str, rr_ttl: int, rr_type: str, rdata_item: JsonNodeT) -> RRecordBase:
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

    def process(self, sn: SchemaNode, ii: InstanceRoute, ch: DataChange):
        debug_confh(self.__class__.__name__ + " triggered")

        base_ii_str = "/dns-zones:zone-data"
        base_ii = DataHelpers.parse_ii(base_ii_str, PathFormat.URL)
        base_ii_len = len(base_ii)
        ii_str = "".join([str(seg) for seg in ii])

        debug_confh("ZoneDataHandler: Change at sn \"{}\", dn \"{}\"".format(sn.name, ii_str))

        # Create new zone with SOA in zone data section
        if (ii == base_ii) and (ch.change_type == ChangeType.CREATE):
            domain_name = ch.data["zone"]["name"]
            def_ttl = ch.data["zone"]["default-ttl"]

            soa = ch.data.get("zone", {}).get("SOA")
            if soa is None:
                return ConfHandlerResult.ERROR

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

        # Add resource record to particular zone
        elif (
                len(ii) == (base_ii_len + 2)) \
                and isinstance(ii[base_ii_len], MemberName) and (ii[base_ii_len].key == "zone") \
                and isinstance(ii[base_ii_len + 1], EntryKeys) \
                and (ch.change_type == ChangeType.CREATE) \
                and (ch.data.get("rrset") is not None):
            domain_name = ii[base_ii_len + 1].keys["name"]
            rr = ch.data.get("rrset", {})
            rr_owner = rr["owner"]
            rr_type = rr.get("type").split(":")[-1]
            rr_ttl = rr.get("ttl")
            if rr_ttl is None:
                # Obtain default ttl from datastore if not specified explicitly
                rr_ttl = self.ds.get_data_root().goto(ii[0:3]).value["default-ttl"]

            for rdata_item in rr["rdata"]:
                new_rr = self._rr_from_rdata_item(domain_name, rr_owner, rr_ttl, rr_type, rdata_item)
                if new_rr is not None:
                    debug_confh("KnotApi: adding new {} RR to zone \"{}\"".format(rr_type, domain_name))
                    knot_api.KNOT.zone_add_record(domain_name, new_rr)

        # Add resource record to particular zone (only specific "rdata" item)
        elif (
                len(ii) == (base_ii_len + 4)) \
                and isinstance(ii[base_ii_len], MemberName) and (ii[base_ii_len].key == "zone") \
                and isinstance(ii[base_ii_len + 1], EntryKeys) \
                and isinstance(ii[base_ii_len + 2], MemberName) and (ii[base_ii_len + 2].key == "rrset") \
                and isinstance(ii[base_ii_len + 3], EntryKeys) \
                and (ch.change_type == ChangeType.CREATE) \
                and (ch.data.get("rdata") is not None):
            domain_name = ii[base_ii_len + 1].keys["name"]
            rdata_item = ch.data.get("rdata", {})
            keys_ii_seg = ii[len(base_ii) + 3]
            rr_owner = keys_ii_seg.keys["owner"]
            rr_type = keys_ii_seg.keys["type"][0].split(":")[-1]

            # Try to use record-specific ttl first
            rr_ttl = self.ds.get_data_root().goto(ii).value.get("ttl")
            if rr_ttl is None:
                # Obtain default ttl from datastore if not specified explicitly
                rr_ttl = self.ds.get_data_root().goto(ii[0:3]).value["default-ttl"]

            new_rr = self._rr_from_rdata_item(domain_name, rr_owner, rr_ttl, rr_type, rdata_item)

            if new_rr is not None:
                debug_confh("KnotApi: adding new {} RR to zone \"{}\"".format(rr_type, domain_name))
                knot_api.KNOT.zone_add_record(domain_name, new_rr)

        # Delete resource record from particular zone
        elif (
                len(ii) == (base_ii_len + 4)) \
                and isinstance(ii[base_ii_len], MemberName) and (ii[base_ii_len].key == "zone") \
                and isinstance(ii[base_ii_len + 1], EntryKeys) \
                and isinstance(ii[base_ii_len + 2], MemberName) and (ii[base_ii_len + 2].key == "rrset") \
                and isinstance(ii[base_ii_len + 3], EntryKeys) \
                and (ch.change_type == ChangeType.DELETE):
            domain_name = ii[base_ii_len + 1].keys["name"]
            keys_ii_seg = ii[len(base_ii) + 3]
            rr_owner = keys_ii_seg.keys["owner"]
            rr_type = keys_ii_seg.keys["type"][0]

            debug_confh("KnotApi: deleting {} RR from zone \"{}\"".format(rr_type, domain_name))
            knot_api.KNOT.zone_del_record(domain_name, rr_owner, rr_type)

        # Delete resource record from particular zone (only specific "rdata" item)
        elif (
                len(ii) == (base_ii_len + 6)) \
                and isinstance(ii[base_ii_len], MemberName) and (ii[base_ii_len].key == "zone") \
                and isinstance(ii[base_ii_len + 1], EntryKeys) \
                and isinstance(ii[base_ii_len + 2], MemberName) and (ii[base_ii_len + 2].key == "rrset") \
                and isinstance(ii[base_ii_len + 3], EntryKeys) \
                and isinstance(ii[base_ii_len + 4], MemberName) and (ii[base_ii_len + 4].key == "rdata") \
                and isinstance(ii[base_ii_len + 5], EntryKeys) \
                and (ch.change_type == ChangeType.DELETE):
            domain_name = ii[base_ii_len + 1].keys["name"]
            keys_ii_seg = ii[len(base_ii) + 3]
            rr_owner = keys_ii_seg.keys["owner"]
            rr_type = keys_ii_seg.keys["type"][0]
            rdata_item = self.ds.get_data_root(previous_version=1).goto(ii).value

            rr_sel = self._rr_from_rdata_item(domain_name, rr_owner, 0, rr_type, rdata_item)

            debug_confh("KnotApi: deleting {} RR from zone \"{}\"".format(rr_type, domain_name))
            knot_api.KNOT.zone_del_record(domain_name, rr_owner, rr_type, selector=rr_sel.rrdata_format())

        else:
            return ConfHandlerResult.ERROR

        return ConfHandlerResult.OK
