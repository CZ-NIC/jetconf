import sys

from enum import Enum
from typing import List, Union, Dict, Any, Optional
from threading import Lock

from .helpers import LogHelpers

try:
    from .libknot.control import KnotCtl, KnotCtlType, KnotCtlError
except ValueError as e:
    print(str(e))
    sys.exit(1)

JsonNodeT = Union[Dict[str, Any], List[Any], str, int]
debug_knot = LogHelpers.create_module_dbg_logger(__name__)


class KnotError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class KnotApiStateError(KnotError):
    pass


class KnotInternalError(KnotError):
    pass


class KnotApiError(KnotError):
    pass


class KnotConfState(Enum):
    NONE = 0
    CONF = 1
    ZONE = 2


class RRecordBase:
    def __init__(self, owner: str, res_type: str, ttl: Optional[int]=None):
        self.owner = owner
        self.type = res_type
        self.ttl = ttl

    def rrdata_format(self) -> str:
        raise NotImplementedError("Not implemented in base class")

    @property
    def ttl_str(self) -> Optional[str]:
        return str(self.ttl) if self.ttl is not None else None


class SOARecord(RRecordBase):
    def __init__(self):
        super().__init__("@", "SOA")
        self.mname = None       # type: str
        self.rname = None       # type: str
        self.serial = None      # type: str
        self.refresh = None     # type: str
        self.retry = None       # type: str
        self.expire = None      # type: str
        self.minimum = None     # type: str

    def rrdata_format(self) -> str:
        return "{} {} {} {} {} {} {}".format(
            self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.minimum
        )


class NSRecord(RRecordBase):
    def __init__(self, owner: str, ttl: Optional[int]=None):
        super().__init__(owner, "NS", ttl)
        self.nsdname = None     # type: str

    def rrdata_format(self) -> str:
        return self.nsdname


class ARecord(RRecordBase):
    def __init__(self, owner: str, ttl: Optional[int]=None):
        super().__init__(owner, "A", ttl)
        self.address = None     # type: str

    def rrdata_format(self) -> str:
        return self.address


class AAAARecord(RRecordBase):
    def __init__(self, owner: str, ttl: Optional[int]=None):
        super().__init__(owner, "AAAA", ttl)
        self.address = None     # type: str

    def rrdata_format(self) -> str:
        return self.address


class MXRecord(RRecordBase):
    def __init__(self, owner: str, ttl: Optional[int]=None):
        super().__init__(owner, "MX", ttl)
        self.preference = None  # type: str
        self.exchange = None    # type: str

    def rrdata_format(self) -> str:
        return self.exchange


class KnotConfig(KnotCtl):
    def __init__(self):
        super().__init__()
        self.sock_path = ""
        self.connected = False
        self.socket_lock = Lock()
        self.conf_state = KnotConfState.NONE

    def set_socket(self, sock_path: str):
        self.sock_path = sock_path

    def knot_connect(self):
        if self.connected:
            raise KnotApiError("Knot socket already opened")

        if not self.socket_lock.acquire(blocking=True, timeout=5):
            raise KnotApiError("Cannot acquire Knot socket lock")

        try:
            self.connect(self.sock_path)
        except KnotCtlError:
            self.socket_lock.release()
            raise KnotApiError("Cannot connect to Knot socket")
        self.connected = True

    def knot_disconnect(self):
        self.send(KnotCtlType.END)
        self.close()
        self.connected = False
        self.socket_lock.release()

    def flush_socket(self):
        pass

    # Starts a new transaction for configuration data
    def begin(self):
        if self.conf_state == KnotConfState.NONE:
            self.send_block("conf-begin")
            try:
                self.receive_block()
                self.conf_state = KnotConfState.CONF
            except KnotCtlError as e:
                raise KnotInternalError(str(e))

    # Starts a new transaction for zone data
    def begin_zone(self):
        if self.conf_state == KnotConfState.NONE:
            self.send_block("zone-begin")
            try:
                self.receive_block()
                self.conf_state = KnotConfState.ZONE
            except KnotCtlError as e:
                raise KnotInternalError(str(e))

    # Commits the internal KnotDNS transaction
    def commit(self):
        if self.conf_state == KnotConfState.CONF:
            self.send_block("conf-commit")
        elif self.conf_state == KnotConfState.ZONE:
            self.send_block("zone-commit")
        else:
            raise KnotApiStateError()

        try:
            self.receive_block()
            self.conf_state = KnotConfState.NONE
        except KnotCtlError as e:
            raise KnotInternalError(str(e))

    # Aborts the internal KnotDNS transaction
    def abort(self):
        if self.conf_state == KnotConfState.CONF:
            self.send_block("conf-abort")
        elif self.conf_state == KnotConfState.ZONE:
            self.send_block("zone-abort")
        else:
            raise KnotApiStateError()

        try:
            self.receive_block()
            self.conf_state = KnotConfState.NONE
        except KnotCtlError as e:
            raise KnotInternalError(str(e))

    # Deletes a whole section from Knot configuration
    def unset_section(self, section: str, identifier: str=None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        self.send_block("conf-unset", section=section, identifier=identifier)
        try:
            resp = self.receive_block()
        except KnotCtlError as e:
            resp = {}
            err_str = str(e)
            if err_str != "not exists":
                raise KnotInternalError(err_str)

        return resp

    # Low-level methods for setting and deleting values from Knot configuration
    def set_item(self, section: str, identifier: Optional[str], item: str, value: str) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        if value is not None:
            if isinstance(value, (int, bool)):
                value = str(value).lower()
            self.send_block("conf-set", section=section, identifier=identifier, item=item, data=value)
            try:
                resp = self.receive_block()
            except KnotCtlError as e:
                raise KnotInternalError(str(e))
        else:
            resp = {}

        return resp

    def unset_item(self, section: str, identifier: Optional[str], item: str, zone: str=None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        self.send_block("conf-unset", section=section, identifier=identifier, item=item, zone=zone)
        try:
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))

        return resp

    def set_item_list(self, section: str, identifier: Optional[str], item: str, value: List[str]) -> List[JsonNodeT]:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        resp_list = []
        for data_item in value:
            self.send_block("conf-set", section=section, identifier=identifier, item=item, data=data_item)
            try:
                resp = self.receive_block()
                resp_list.append(resp)
            except KnotCtlError as e:
                raise KnotInternalError(str(e))

        return resp_list

    # Returns a status data of all or one specific DNS zone
    def zone_status(self, domain_name: str=None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.send_block("zone-status", zone=domain_name)
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))
        return resp

    # Purges all zone data
    def zone_purge(self, domain_name: str = None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        self.send_block("zone-purge", zone=domain_name)
        try:
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))

        return resp

    # Adds a new DNS zone to configuration section
    def zone_new(self, domain_name: str) -> JsonNodeT:
        resp = self.set_item(section="zone", identifier=None, item="domain", value=domain_name)
        return resp

    # Removes a DNS zone from configuration section
    def zone_remove(self, domain_name: str, purge_data: bool) -> JsonNodeT:
        resp = self.unset_item(section="zone", identifier=domain_name, item="domain")
        if purge_data:
            self.zone_purge(domain_name)
        return resp

    # Adds a resource record to DNS zone
    def zone_add_record(self, domain_name: str, rr: RRecordBase) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            res_data = rr.rrdata_format()
            self.send_block("zone-set", zone=domain_name, owner=rr.owner, ttl=rr.ttl_str, rtype=rr.type, data=res_data)

            debug_knot("Inserting zone \"{}\" RR, type=\"{}\", owner=\"{}\", ttl={}, data=\"{}\"".format(
                domain_name, rr.type, rr.owner, rr.ttl_str, res_data
            ))
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))
        return resp

    # Removes a resource record from DNS zone
    # If the zone contains two or more records with the same owner and type, selector parameter can specify
    # which one to remove. Usually it is the same as record data.
    def zone_del_record(self, domain_name: str, owner: str, rr_type: str, selector: str=None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.send_block("zone-unset", zone=domain_name, owner=owner, rtype=rr_type, data=selector)
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))
        return resp

    # Reads zone data and converts them to YANG model compliant data tree
    def zone_read(self, domain_name: str) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.send_block("zone-read", zone=domain_name)
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))

        if domain_name[-1] != ".":
            domain_name += "."

        return resp[domain_name]

    # Reads all configuration data and converts them to YANG model compliant data tree
    def config_read(self) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.send_block("conf-read")
            resp = self.receive_block()
        except KnotCtlError as e:
            raise KnotInternalError(str(e))

        out_conf_dnss = {}

        out_conf_data = {
            "dns-server:dns-server": out_conf_dnss
        }

        out_conf_dnss["description"] = "Configuration acquired from KnotDNS control socket"

        # "server" section
        server_in = resp.get("server")
        if server_in is not None:
            server_out = {}

            server_listen_in = server_in.get("listen")
            if server_listen_in is not None:
                server_ep_list = []
                ep_name = 1

                for ep in server_listen_in:
                    ep_splitted = ep.split("@")
                    listen_ep = {
                        "name": str(ep_name),
                        "ip-address": ep_splitted[0],
                        "port": int(ep_splitted[1])
                    }
                    ep_name += 1
                    server_ep_list.append(listen_ep)
                server_out["listen-endpoint"] = server_ep_list

            server_rundir_in = server_in.get("rundir")
            if (server_rundir_in is not None) and (len(server_rundir_in) >= 1):
                server_out["filesystem-paths"] = {
                    "run-time-dir": server_rundir_in[0]
                }

            out_conf_dnss["server-options"] = server_out

        # "log" section
        log_in = resp.get("log")
        if log_in is not None:
            log_out = []

            for tgt, rel_dict in log_in.items():
                log_item_out = {
                    "target": tgt
                }
                for rel, val in rel_dict.items():
                    log_item_out[rel] = val[0]
                log_out.append(log_item_out)

            out_conf_dnss["knot-dns:log"] = log_out

        # "acl" section
        acl_in = resp.get("acl")
        if acl_in is not None:
            acl_out = []

            for acl_name, acl_dict in acl_in.items():
                acl_item_out = {
                    "name": acl_name,
                    "operation": acl_dict["action"]
                }

                acl_item_nw_out = []
                nw_name = 1
                for nw_adr in acl_dict["address"]:
                    acl_item_nw_item_out = {
                        "name": str(nw_name),
                        "ip-prefix": nw_adr + "/32"
                    }
                    acl_item_nw_out.append(acl_item_nw_item_out)

                acl_item_out["network"] = acl_item_nw_out
                acl_out.append(acl_item_out)

            out_conf_dnss["access-control-list"] = acl_out

        # "template" section
        template_in = resp.get("template")
        if template_in is not None:
            template_out = []

            for template_name, template_dict in template_in.items():
                template_item_out = {
                    "name": template_name
                }

                try:
                    semantic_checks_str = template_dict["semantic-checks"][0]  # values: "on", "off"
                    semantic_checks_bool = {"on": True, "off": False}[semantic_checks_str]
                    template_item_out["knot-dns:semantic-checks"] = semantic_checks_bool
                except (KeyError, IndexError, ValueError):
                    pass

                try:
                    storage = template_dict["storage"][0]
                    template_item_out["zones-dir"] = storage
                except (KeyError, IndexError):
                    pass

                try:
                    zonefile_sync = template_dict["zonefile-sync"][0]
                    template_item_out["journal"] = {
                        "zone-file-sync-delay": int(zonefile_sync)
                    }
                except (KeyError, IndexError, ValueError):
                    pass

                template_out.append(template_item_out)

            out_conf_dnss["zones"] = {
                "template": template_out
            }

        # "zone" section
        zone_in = resp.get("zone")
        if zone_in is not None:
            zone_out = []

            for domain, zone_dict in zone_in.items():
                zone_item_out = {
                    "domain": domain.rstrip(".")
                }

                try:
                    zonefile = zone_dict["file"][0]
                    zone_item_out["file"] = zonefile
                except (KeyError, IndexError):
                    pass

                try:
                    zone_acl = zone_dict["acl"]
                    zone_item_out["access-control-list"] = zone_acl
                except KeyError:
                    pass

                zone_out.append(zone_item_out)

            try:
                out_conf_dnss_zone = out_conf_dnss["zone"]
                out_conf_dnss_zone["zone"] = zone_out
            except KeyError:
                out_conf_dnss["zones"] = {
                    "zone": zone_out
                }

        # print(json.dumps(out_conf_data, indent=4, sort_keys=True))
        return out_conf_data


# Connects to Knot control socket and begins a new transaction (config or zone)
def knot_connect(transaction_opts: Optional[JsonNodeT]) -> bool:
    debug_knot("Connecting to KNOT socket")
    KNOT.knot_connect()

    if transaction_opts in ("config", None):
        debug_knot("Starting new KNOT config transaction")
        KNOT.begin()
    elif transaction_opts == "zone":
        debug_knot("Starting new KNOT zone transaction")
        KNOT.begin_zone()

    return True


# Commits current Knot internal transaction and disconnects from control socket
def knot_disconnect(transaction_opts: Optional[JsonNodeT], failed: bool=False) -> bool:
    KNOT.flush_socket()

    if failed:
        debug_knot("Aborting KNOT transaction")
        KNOT.abort()
        retval = True
    else:
        debug_knot("Commiting KNOT transaction")
        KNOT.commit()
        retval = True

    debug_knot("Disonnecting from KNOT socket")
    KNOT.knot_disconnect()

    return retval


KNOT = KnotConfig()
