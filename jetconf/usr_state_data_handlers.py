import json

from colorlog import error

from yangson.datamodel import DataModel
from yangson.instance import InstanceRoute, InstanceNode, EntryKeys, NonexistentInstance, RootNode

from .knot_api import KNOT, KnotInternalError
from .helpers import DataHelpers, JsonNodeT
from .handler_list import StateDataHandlerList
from .usr_op_handlers import OP_HANDLERS_IMPL as OH, KnotZoneCmd


class StateNonexistentInstance(NonexistentInstance):
    def __init__(self, ii: InstanceRoute, text: str) -> None:
        self.ii = ii
        self.text = text

    def __str__(self):
        return str(self.ii) + ": " + self.text


class StateNodeHandlerBase:
    def __init__(self, data_model: DataModel, schema_path: str):
        self.data_model = data_model
        self.sch_pth = schema_path
        self.schema_node = data_model.get_data_node(self.sch_pth)


class ContainerNodeHandlerBase(StateNodeHandlerBase):
    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        pass


class ListNodeHandlerBase(StateNodeHandlerBase):
    def generate_list(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        pass

    def generate_item(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        pass


class ZoneSigningStateHandler(ContainerNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-server:dns-server-state/zone/dnssec-signing:dnssec-signing")

    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        print("zone_state_signing_handler, ii = {}".format(node_ii))
        domain_name = node_ii[2].keys.get(("domain", None)) + "."

        zone_signing = {
            "enabled": True,
            "key": [
                {
                    "key-id": "d3a9fd3b36a6be275adea2b67c6e82b27ca30e90",
                    "key-tag": 30348,
                    "algorithm": "RSASHA256",
                    "size": 2048,
                    "flags": "zone-key secure-entry-point",
                    "created": "2015-06-18T18:02:45+02:00",
                    "publish": "2015-06-18T19:00:00+02:00",
                    "retire": "2015-07-18T18:02:45+02:00",
                    "remove": "2015-07-25T00:00:00+02:00"
                }
            ]
        }

        retval = zone_signing

        return retval


class ZoneStateHandler(ListNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-server:dns-server-state/zone")

    def generate_list(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        zones_list = []

        KNOT.knot_connect()
        # Request status of all zones
        resp = KNOT.zone_status()
        KNOT.knot_disconnect()

        for domain_name, status_data in resp.items():
            try:
                zone_obj = {
                    "domain": domain_name.rstrip("."),
                    "class": "IN",
                    "serial": int(status_data.get("serial")),
                    "server-role": status_data.get("type")
                }

                zones_list.append(zone_obj)
            except ValueError:
                error("Error parsing Knot zone status data")

        return zones_list

    def generate_item(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        zone_obj = {}

        # Request status of specific zone
        KNOT.knot_connect()
        domain_desired = node_ii[2].keys.get(("domain", None))
        resp = KNOT.zone_status(domain_desired)
        KNOT.knot_disconnect()

        domain_name, status_data = tuple(resp.items())[0]
        try:
            zone_obj = {
                "domain": domain_name.rstrip("."),
                "class": "IN",
                "serial": int(status_data.get("serial")),
                "server-role": status_data.get("type")
            }
        except ValueError:
            error("Error parsing Knot zone status data")

        return zone_obj


class ZoneDataStateHandler(ListNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-zones-state:zone")

    @staticmethod
    def _transform_zone(domain_name: str, domain_data_raw: JsonNodeT) -> JsonNodeT:
        zone_out = {
            "name": domain_name.rstrip("."),
            "class": "IN",
            "rrset": []
        }

        rrset_out = zone_out["rrset"]

        for owner, rrs in domain_data_raw.items():
            # print("rrs={}".format(rrs))
            for rr_type, rr in rrs.items():
                # print("rr={}".format(rr))
                if rr_type not in ("SOA", "A", "AAAA", "NS", "MX", "TXT", "TLSA", "CNAME"):
                    continue

                ttl = int(rr["ttl"])
                rr_data_list = rr["data"]

                new_rr_out_rdata_list = []
                new_rr_out = {
                    "owner": owner.rstrip("."),
                    "type": "iana-dns-parameters:" + rr_type,
                    "ttl": ttl,
                    "rdata": new_rr_out_rdata_list
                }

                for rr_data in rr_data_list:
                    new_rr_out_rdata_values = {}
                    new_rr_out_rdata = {
                        rr_type: new_rr_out_rdata_values
                    }

                    if rr_type == "SOA":
                        rr_data = rr_data.split()
                        try:
                            new_rr_out_rdata_values["mname"] = rr_data[0].rstrip(".")
                            new_rr_out_rdata_values["rname"] = rr_data[1].rstrip(".")
                            new_rr_out_rdata_values["serial"] = int(rr_data[2])
                            new_rr_out_rdata_values["refresh"] = int(rr_data[3])
                            new_rr_out_rdata_values["retry"] = int(rr_data[4])
                            new_rr_out_rdata_values["expire"] = int(rr_data[5])
                            new_rr_out_rdata_values["minimum"] = int(rr_data[6])
                        except (IndexError, ValueError) as e:
                            print(str(e))
                    elif rr_type in ("A", "AAAA"):
                        new_rr_out_rdata_values["address"] = rr_data
                    elif rr_type == "NS":
                        new_rr_out_rdata_values["nsdname"] = rr_data.rstrip(".")
                    elif rr_type == "MX":
                        rr_data = rr_data.split()
                        new_rr_out_rdata_values["preference"] = rr_data[0]
                        new_rr_out_rdata_values["exchange"] = rr_data[1].rstrip(".")
                    elif rr_type == "TXT":
                        new_rr_out_rdata_values["txt-data"] = rr_data.strip(" \"")
                    elif rr_type == "TLSA":
                        cert_usage_enum = {
                            "0": "PKIX-TA",
                            "1": "PKIX-EE",
                            "2": "DANE-TA",
                            "3": "DANE-EE",
                            "255": "PrivCert"
                        }
                        sel_enum = {
                            "0": "Cert",
                            "1": "SPKI",
                            "255": "PrivSel"
                        }
                        match_type_enum = {
                            "0": "Full",
                            "1": "SHA2-256",
                            "2": "SHA2-512",
                            "255": "PrivMatch"
                        }
                        rr_data = rr_data.split()
                        new_rr_out_rdata_values["certificate-usage"] = cert_usage_enum[rr_data[0]]
                        new_rr_out_rdata_values["selector"] = sel_enum[rr_data[1]]
                        new_rr_out_rdata_values["matching-type"] = match_type_enum[rr_data[2]]
                        new_rr_out_rdata_values["certificate-association-data"] = rr_data[3]
                    elif rr_type == "CNAME":
                        new_rr_out_rdata_values["cname"] = rr_data

                    new_rr_out_rdata_list.append(new_rr_out_rdata)

                rrset_out.append(new_rr_out)

        return zone_out

    def generate_list(self, node_ii: InstanceRoute, username: str, staging: bool):
        # Request contents of all zones
        KNOT.knot_connect()

        # Get list of zones with zone-status command
        resp = KNOT.zone_status()

        # Read zone contents
        retval = []
        for domain_name in resp.keys():
            resp_zone = KNOT.zone_read(domain_name)
            retval.append(self._transform_zone(domain_name, resp_zone))

        KNOT.knot_disconnect()

        return retval

    def generate_item(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        # Request contents of specific zone
        KNOT.knot_connect()
        domain_name = node_ii[1].keys.get(("name", None))

        # if domain_name[-1] != ".":
        #     domain_name_dot = domain_name + "."
        # else:
        #     domain_name_dot = domain_name

        resp = KNOT.zone_read(domain_name)
        KNOT.knot_disconnect()

        zone_data = self._transform_zone(domain_name, resp)

        if staging:
            print("{}: generating staging state data".format(username))
            usr_op_journal = OH.op_journal.get(username, [])
            for knot_op in usr_op_journal:
                input_args = knot_op.op_input
                input_domain = input_args["dns-zone-rpcs:zone"]
                if domain_name != input_domain:
                    continue

                if knot_op.cmd == KnotZoneCmd.SET:
                    input = knot_op.op_input
                    rrset_out = zone_data["rrset"]

                    rr1 = None

                    for rr in rrset_out:
                        owner_eq = rr["owner"] == input["dns-zone-rpcs:owner"]
                        input_type_str = input["dns-zone-rpcs:type"][1] + ":" + input["dns-zone-rpcs:type"][0]
                        type_eq = rr["type"] == input_type_str
                        ttl_eq = rr["ttl"] == input["dns-zone-rpcs:ttl"]

                        if owner_eq and type_eq and ttl_eq:
                            rr1 = rr
                            break

                    if rr1 is not None:
                        # Suitable rr already present
                        rdata_out = rr1["rdata"]
                        type_no_ns = input["dns-zone-rpcs:type"][0]
                        rdata_in_key = "dns-zone-rpcs:" + type_no_ns
                        rdata_in = input[rdata_in_key]
                        rdata_item = {
                            type_no_ns: rdata_in
                        }
                        rdata_out.append(rdata_item)
                    else:
                        # Create new rr
                        type_no_ns = input["dns-zone-rpcs:type"][0]
                        rdata_in_key = "dns-zone-rpcs:" + type_no_ns
                        rdata_in = input[rdata_in_key]
                        rr_new = {
                            "owner": input["dns-zone-rpcs:owner"],
                            "type": input["dns-zone-rpcs:type"][1] + ":" + input["dns-zone-rpcs:type"][0],
                            "ttl": input["dns-zone-rpcs:ttl"],
                            "rdata": [
                                {
                                    type_no_ns: rdata_in
                                }
                            ]
                        }
                        rrset_out.append(rr_new)

                elif knot_op.cmd == KnotZoneCmd.UNSET:
                    # zone-unset zone owner [type [rdata]]
                    input = knot_op.op_input
                    rrset_out = zone_data["rrset"]

                    owner_in = input["dns-zone-rpcs:owner"]
                    try:
                        type_no_ns = input["dns-zone-rpcs:type"][0]
                        input_type_str = input["dns-zone-rpcs:type"][1] + ":" + input["dns-zone-rpcs:type"][0]
                    except (IndexError, KeyError):
                        type_no_ns = None
                        input_type_str = None

                    if type_no_ns is not None:
                        try:
                            rdata_in_key = "dns-zone-rpcs:" + type_no_ns
                            rdata_in = input[rdata_in_key]
                        except (IndexError, KeyError):
                            rdata_in = None

                        if rdata_in is not None:
                            # Owner, type and rdata is known
                            found_positions = list(filter(lambda n: (rrset_out[n]["owner"] == owner_in) and (rrset_out[n]["type"] == input_type_str), range(len(rrset_out))))
                            # print("found_positions_otr={}".format(found_positions))
                            for pos in found_positions:
                                rr_rdata = rrset_out[pos]["rdata"]
                                found_positions_rdata = list(filter(lambda n: (rr_rdata[n][type_no_ns] == dict(rdata_in.items())), range(len(rr_rdata))))
                                # print("found_positions_rdata={}".format(found_positions_rdata))
                                for pos_rd in found_positions_rdata:
                                    rr_rdata.pop(pos_rd)
                        else:
                            # Owner and type is known
                            found_positions = list(filter(lambda n: (rrset_out[n]["owner"] == owner_in) and (rrset_out[n]["type"] == input_type_str), range(len(rrset_out))))
                            # print("found_positions_ot={}".format(found_positions))
                            for pos in found_positions:
                                rrset_out.pop(pos)
                    else:
                        # Just owner is specified
                        found_positions = list(filter(lambda n: rrset_out[n]["owner"] == owner_in, range(len(rrset_out))))
                        # print("found_positions_o={}".format(found_positions))
                        for pos in found_positions:
                            rrset_out.pop(pos)

        return zone_data


#     +---x zone-set
#     |  +---w input
#     |     +---w zone          inet:domain-name
#     |     +---w owner         domain-name
#     |     +---w type          identityref
#     |     +---w ttl           time-interval
#     |     +---w (rdata-content)
#     |        +--:(SOA)
#     |        |  +---w SOA
#     |        |     +---w mname      domain-name
#     |        |     +---w rname      domain-name
#     |        |     +---w serial     yang:counter32
#     |        |     +---w refresh    time-interval
#     |        |     +---w retry      time-interval
#     |        |     +---w expire     time-interval
#     |        |     +---w minimum    time-interval
#     |        +--:(A)
#     |        |  +---w A
#     |        |     +---w address    inet:ipv4-address-no-zone


# "class": "IN",
# "name": "turris.cz",
# "rrset": [
#     {
#         "type": "iana-dns-parameters:CNAME",
#         "ttl": 1800,
#         "owner": "buy.turris.cz",
#         "rdata": [
#             {
#                 "CNAME": {
#                     "cname": "omnia.turris.cz."
#                 }
#             }
#         ]
#     },
#     {
#         "type": "iana-dns-parameters:A",
#         "ttl": 1800,
#         "owner": "at.turris.cz",
#         "rdata": [
#             {
#                 "A": {
#                     "address": "217.31.192.107"
#                 }
#             }
#         ]
#     },

class PokusStateHandler(ContainerNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-server:dns-server/access-control-list/network/pokus")

    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        print("pokus_handler, ii = {}".format(node_ii))
        try:
            acl_name = node_ii[2].keys.get(("name", None))
        except IndexError:
            acl_name = None

        return {"pok": "Name: {}".format(acl_name)}


# Instantiate state data handlers
def create_zone_state_handlers(handler_list: "StateDataHandlerList", dm: DataModel):
    zsh = ZoneStateHandler(dm)
    zdsh = ZoneDataStateHandler(dm)
    psh = PokusStateHandler(dm)
    handler_list.register_handler(zsh)
    handler_list.register_handler(zdsh)
    handler_list.register_handler(psh)
