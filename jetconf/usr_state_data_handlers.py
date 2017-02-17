import json

from colorlog import error

from yangson.datamodel import DataModel
from yangson.instance import InstanceRoute, InstanceNode, EntryKeys, NonexistentInstance, RootNode

from .knot_api import KNOT, KnotInternalError
from .helpers import DataHelpers, JsonNodeT
from .handler_list import StateDataHandlerList


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
    def generate_node(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
        pass


class ListNodeHandlerBase(StateNodeHandlerBase):
    def generate_list(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
        pass

    def generate_item(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
        pass


class ZoneSigningStateHandler(ContainerNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-server:dns-server-state/zone/dnssec-signing:dnssec-signing")

    def generate_node(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
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

    def generate_list(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
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

    def generate_item(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
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

    def generate_item(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
        # Request contents of specific zone
        KNOT.knot_connect()
        domain_name = node_ii[1].keys.get(("name", None))

        # if domain_name[-1] != ".":
        #     domain_name_dot = domain_name + "."
        # else:
        #     domain_name_dot = domain_name

        resp = KNOT.zone_read(domain_name)
        KNOT.knot_disconnect()

        zone_out = {
            "name": domain_name,
            "class": "IN",
            "rrset": []
        }

        rrset_out = zone_out["rrset"]

        for owner, rrs in resp.items():
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


class PokusStateHandler(ContainerNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-server:dns-server/access-control-list/network/pokus")

    def generate_node(self, node_ii: InstanceRoute, staging: bool) -> JsonNodeT:
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
