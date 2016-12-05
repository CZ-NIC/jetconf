from colorlog import error
from typing import Dict, Any, List, Union

from yangson.datamodel import DataModel
from yangson.instance import InstanceRoute, InstanceNode, EntryKeys, NonexistentInstance

from jetconf.knot_api import KnotInternalError
from . import knot_api
from .helpers import DataHelpers, JsonNodeT
from .handler_list import StateDataHandlerList


class StateNonexistentInstance(NonexistentInstance):
    def __init__(self, ii: InstanceRoute, text: str) -> None:
        self.ii = ii
        self.text = text

    def __str__(self):
        return str(self.ii) + ": " + self.text


class StateNodeHandlerBase:
    def __init__(self, data_model: DataModel):
        self.data_model = data_model
        self.sch_pth = None
        self.schema_node = None
        self.member_handlers = {}  # type: Dict[str, StateNodeHandlerBase]

    def add_member_handler(self, member: str, handler: "StateNodeHandlerBase"):
        self.member_handlers[member] = handler

    def update_node(self, node_ii: InstanceRoute, data_root: InstanceNode, with_container: bool) -> InstanceNode:
        pass

    def gen_container(self, ii: InstanceRoute, data: JsonNodeT) -> JsonNodeT:
        return DataHelpers.node2doc(ii, data)


class ZoneSigningStateHandler(StateNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model)
        self.sch_pth = "/dns-server:dns-server-state/zone/dnssec-signing:dnssec-signing"
        self.schema_node = data_model.get_data_node(self.sch_pth)

    def update_node(self, node_ii: InstanceRoute, data_root: InstanceNode, with_container: bool) -> InstanceNode:
        print("zone_state_signing_handler, ii = {}".format(node_ii))
        zone_name = node_ii[2].keys.get("domain")

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
                    # "activate": str(datetime.now()),
                    "retire": "2015-07-18T18:02:45+02:00",
                    "remove": "2015-07-25T00:00:00+02:00"
                }
            ]
        }

        if with_container:
            retval = self.gen_container(node_ii[0:4], zone_signing)
        else:
            retval = zone_signing

        return retval


class ZoneStateHandler(StateNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model)
        self.sch_pth = "/dns-server:dns-server-state/zone"
        self.schema_node = data_model.get_data_node(self.sch_pth)

    def update_node(self, node_ii: InstanceRoute, data_root: InstanceNode, with_container: bool) -> InstanceNode:
        node_ii_str = sch_pth = "".join([str(seg) for seg in node_ii])
        print("zone_state_handler, ii = {}".format(node_ii_str))

        # Request status of specific zone
        if len(node_ii) > 2:
            zone_name = node_ii[2].keys.get("domain") + "."

            try:
                resp = knot_api.KNOT.zone_status(zone_name)
                resp = resp.get(zone_name)
            except KnotInternalError:
                raise StateNonexistentInstance(node_ii, "No such zone")

            zone_obj = {
                "domain": zone_name,
                "class": "IN",
                "serial": int(resp.get("serial")),
                "server-role": resp.get("type")
            }

            if with_container:
                retval = self.gen_container(node_ii[0:3], zone_obj)
            else:
                retval = zone_obj

            for m, h in self.member_handlers.items():
                zone_obj[m] = h.update_node(node_ii, data_root, False)

        # Request status of all zones
        else:
            resp = knot_api.KNOT.zone_status()
            zones_list = []

            for zone_name, zone_status in resp.items():
                try:
                    zone_name = zone_name.rstrip(".")
                    zone_obj = {
                        "domain": zone_name,
                        "class": "IN",
                        "serial": int(zone_status.get("serial")),
                        "server-role": zone_status.get("type")
                    }

                    for m, h in self.member_handlers.items():
                        zone_obj[m] = h.update_node(node_ii + [EntryKeys({"domain": zone_name})], data_root, False)

                    zones_list.append(zone_obj)
                except ValueError:
                    error("Error parsing Knot zone status data")

            if with_container:
                retval = self.gen_container(node_ii[0:2], zones_list)
            else:
                retval = zones_list

        return retval


# Create handler hierarchy
def create_zone_state_handlers(handler_list: "StateDataHandlerList", dm: DataModel):
    # zssh = ZoneSigningStateHandler(dm)
    # handler_list.register_handler(zssh)

    zsh = ZoneStateHandler(dm)
    # zsh.add_member_handler("dnssec-signing:dnssec-signing", zssh)
    handler_list.register_handler(zsh)