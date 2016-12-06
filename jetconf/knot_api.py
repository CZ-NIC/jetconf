from enum import Enum
from typing import List, Union, Dict, Any, Optional
from threading import Lock

from .libknot.control import KnotCtl, KnotCtlType
from .config import CONFIG
from .helpers import LogHelpers

KNOT = None     # type: KnotConfig
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
    def __init__(self, sock_path: str):
        super().__init__()
        self.sock_path = sock_path
        self.connected = False
        self.socket_lock = Lock()
        self.conf_state = KnotConfState.NONE

    def knot_connect(self):
        if self.connected:
            raise KnotApiError("Knot socket already opened")

        if not self.socket_lock.acquire(blocking=True, timeout=5):
            raise KnotApiError("Cannot acquire Knot socket lock")

        try:
            self.connect(self.sock_path)
        except Exception:
            self.socket_lock.release()
            raise KnotApiError("Cannot connect to Knot socket")
        self.connected = True

    def knot_disconnect(self):
        self.send(KnotCtlType.END)
        self.close()
        self.connected = False
        self.socket_lock.release()

    def flush_socket(self):
        self.set_timeout(1)
        while True:
            try:
                self.receive_block()
            except Exception as e:
                if str(e) == "connection timeout":
                    debug_knot("socket flushed")
                    break

    # Starts a new transaction for configuration data
    def begin(self):
        if self.conf_state == KnotConfState.NONE:
            self.send_block("conf-begin")
            try:
                self.receive_block()
                self.conf_state = KnotConfState.CONF
            except Exception as e:
                raise KnotInternalError(str(e))

    # Starts a new transaction for zone data
    def begin_zone(self):
        if self.conf_state == KnotConfState.NONE:
            self.send_block("zone-begin")
            try:
                self.receive_block()
                self.conf_state = KnotConfState.ZONE
            except Exception as e:
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
        except Exception as e:
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
        except Exception as e:
            raise KnotInternalError(str(e))

    # Deletes a whole section from Knot configuration
    def unset_section(self, section: str, identifier: str=None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        self.send_block("conf-unset", section=section, identifier=identifier)
        try:
            resp = self.receive_block()
        except Exception as e:
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
            except Exception as e:
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
        except Exception as e:
            raise KnotInternalError(str(e))

        return resp

    def set_item_list(self, section: str, identifier: Optional[str], item: str, value: List[str]) -> List[JsonNodeT]:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        resp_list = []
        if value is not None:
            for data_item in value:
                self.send_block("conf-set", section=section, identifier=identifier, item=item, data=data_item)
                try:
                    resp = self.receive_block()
                    resp_list.append(resp)
                except Exception as e:
                    raise KnotInternalError(str(e))

        return resp_list

    # Returns a status data of all or one specific DNS zone
    def zone_status(self, domain_name: str=None) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.send_block("zone-status", zone=domain_name)
            resp = self.receive_block()
        except Exception as e:
            raise KnotInternalError(str(e))
        return resp

    # Adds a new DNS zone to configuration section
    def zone_new(self, domain_name: str) -> JsonNodeT:
        resp = self.set_item(section="zone", identifier=None, item="domain", value=domain_name)
        return resp

    # Removes a DNS zone from configuration section
    def zone_remove(self, domain_name: str) -> JsonNodeT:
        resp = self.unset_item(section="zone", identifier=None, item="domain", zone=domain_name)
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
        except Exception as e:
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
        except Exception as e:
            raise KnotInternalError(str(e))
        return resp


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


def knot_global_init():
    global KNOT
    if KNOT is None:
        KNOT = KnotConfig(CONFIG["KNOT"]["SOCKET"])
    else:
        raise ValueError("Knot API already instantiated")
