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
    def generate_node(self, node_ii: InstanceRoute, data_root: InstanceNode) -> InstanceNode:
        pass


class ListNodeHandlerBase(StateNodeHandlerBase):
    def generate_list(self, node_ii: InstanceRoute, data_root: InstanceNode) -> InstanceNode:
        pass

    def generate_item(self, node_ii: InstanceRoute, data_root: InstanceNode) -> InstanceNode:
        pass


class ZoneSigningStateHandler(ContainerNodeHandlerBase):
    def __init__(self, data_model: DataModel):
        super().__init__(data_model, "/dns-server:dns-server-state/zone/dnssec-signing:dnssec-signing")

    def generate_node(self, node_ii: InstanceRoute, data_root: InstanceNode) -> InstanceNode:
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

    def generate_list(self, node_ii: InstanceRoute, data_root: InstanceNode) -> InstanceNode:
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

    def generate_item(self, node_ii: InstanceRoute, data_root: InstanceNode) -> InstanceNode:
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


# Instantiate state data handlers
def create_zone_state_handlers(handler_list: "StateDataHandlerList", dm: DataModel):
    # zssh = ZoneSigningStateHandler(dm)
    # handler_list.register_handler(zssh)

    zsh = ZoneStateHandler(dm)
    handler_list.register_handler(zsh)