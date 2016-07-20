from datetime import datetime
from typing import Dict, Any

from yangson.datamodel import DataModel
from yangson.instance import InstanceIdentifier, InstanceNode

from .libknot.control import KnotCtl
from .knot_api import KNOT, KnotConfig

JsonNodeT = Dict[str, Any]


class StateNodeHandlerBase:
    def __init__(self, data_model: DataModel, ctl: KnotCtl):
        self.data_model = data_model
        self.sch_pth = None
        self.schema_node = None
        self.knotctl = ctl
        self.member_handlers = {}  # type: Dict[str, StateNodeHandlerBase]

    def add_member_handler(self, member: str, handler: "StateNodeHandlerBase"):
        self.member_handlers[member] = handler

    def update_node(self, node_ii: InstanceIdentifier, data_root: InstanceNode) -> InstanceNode:
        pass


class ZoneSigningStateHandler(StateNodeHandlerBase):
    def __init__(self, data_model: DataModel, ctl: KnotCtl):
        super().__init__(data_model, ctl)
        self.sch_pth = "/dns-server:dns-server-state/zone/dnssec-signing:dnssec-signing"
        self.schema_node = data_model.get_data_node(self.sch_pth)

    def update_node(self, node_ii: InstanceIdentifier, data_root: InstanceNode) -> InstanceNode:
        print("zone_state_signing_handler, ii = {}".format(node_ii))
        zone_name = node_ii[2].keys.get("domain")

        zone_signing = {
            "key": [
                {
                    "key-id": "d3a9fd3b36a6be275adea2b67c6e82b27ca30e90",
                    "key-tag": 30348,
                    "algorithm": "RSASHA256",
                    "length": 2048,
                    "flags": "zone-key secure-entry-point",
                    "created": "2015-06-18T18:02:45+02:00",
                    "publish": "2015-06-18T19:00:00+02:00",
                    # "activate": str(datetime.now()),
                    "retire": "2015-07-18T18:02:45+02:00",
                    "remove": "2015-07-25T00:00:00+02:00"
                }
            ]
        }

        old_node = data_root.goto(node_ii[0:4])
        new_node = self.schema_node.from_raw(zone_signing)
        new_inst = old_node.update(new_node)
        return new_inst


class ZoneStateHandler(StateNodeHandlerBase):
    def __init__(self, data_model: DataModel, ctl: KnotCtl):
        super().__init__(data_model, ctl)
        self.sch_pth = "/dns-server:dns-server-state/zone"
        self.schema_node = data_model.get_data_node(self.sch_pth)

    def update_node(self, node_ii: InstanceIdentifier, data_root: InstanceNode) -> InstanceNode:
        print("zone_state_handler, ii = {}".format(node_ii))

        # Request status of specific zone
        if len(node_ii) > 2:
            zone_name = node_ii[2].keys.get("domain")

            self.knotctl.send_block("zone-status", zone=zone_name)
            resp = self.knotctl.receive_block()
            resp = resp.get(zone_name + ".")

            zone_obj = {
                "domain": zone_name,
                "class": "IN",
                "serial": int(resp.get("serial")[0]),
                "server-role": resp.get("type")[0]
            }

            old_node = data_root.goto(node_ii[0:3])
            new_node = self.schema_node.from_raw([zone_obj])[0]
            new_inst = old_node.update(new_node)

            for m, h in self.member_handlers.items():
                new_inst = new_inst.new_member(m, h.update_node(node_ii, data_root).value).up()

        # Request status of all zones
        else:
            self.knotctl.send_block("zone-status")
            resp = self.knotctl.receive_block()

            zones_list = []

            for zone_name, zone_status in resp.items():
                zone_obj = {
                    "domain": zone_name[0:-1],
                    "class": "IN",
                    "serial": int(zone_status.get("serial")[0]),
                    "server-role": zone_status.get("type")[0]
                }
                zones_list.append(zone_obj)

            old_node = data_root.goto(node_ii[0:2])
            new_node = self.schema_node.from_raw(zones_list)
            new_inst = old_node.update(new_node)

            for m, h in self.member_handlers.items():
                new_inst = new_inst.new_member(m, h.update_node(node_ii, data_root).value).up()

        return new_inst


# Create handler hierarchy
def create_zone_state_handlers(handler_list: "StateDataHandlerList", dm: DataModel):
    zssh = ZoneSigningStateHandler(dm, KNOT)
    handler_list.register_handler(zssh)

    zsh = ZoneStateHandler(dm, KNOT)
    # zsh.add_member_handler("dnssec-signing:dnssec-signing", zssh)
    handler_list.register_handler(zsh)