from enum import Enum
from typing import List, Union, Dict, Any, Optional
from threading import Lock
from colorlog import info

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

    def begin(self):
        if self.conf_state == KnotConfState.NONE:
            self.send_block("conf-begin")
            try:
                self.receive_block()
                # print(">>> CONF BEGIN")
                self.conf_state = KnotConfState.CONF
            except Exception as e:
                raise KnotInternalError(str(e))

    def begin_zone(self):
        if self.conf_state == KnotConfState.NONE:
            self.send_block("zone-begin")
            try:
                self.receive_block()
                # print(">>> ZONE BEGIN")
                self.conf_state = KnotConfState.ZONE
            except Exception as e:
                raise KnotInternalError(str(e))

    def commit(self):
        if self.conf_state == KnotConfState.CONF:
            self.send_block("conf-commit")
            try:
                self.receive_block()
                self.conf_state = KnotConfState.NONE
            except Exception as e:
                raise KnotInternalError(str(e))
        else:
            raise KnotApiStateError()

    def commit_zone(self):
        if self.conf_state == KnotConfState.ZONE:
            self.send_block("zone-commit")
            try:
                self.receive_block()
                self.conf_state = KnotConfState.NONE
            except Exception as e:
                raise KnotInternalError(str(e))
        else:
            raise KnotApiStateError()

    def set_item(self, item=None, section=None, identifier=None, zone=None, data: str=None):
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        if data is not None:
            if isinstance(data, (int, bool)):
                data = str(data).lower()
            self.send_block("conf-set", section=section, identifier=identifier, item=item, zone=zone, data=data)
        else:
            self.send_block("conf-unset", section=section, identifier=identifier, item=item, zone=zone)

    def set_item_list(self, item=None, section=None, identifier=None, zone=None, data: List[str]=None):
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        self.send_block("conf-unset", section=section, identifier=identifier, item=item, zone=zone)
        if data is None:
            return

        for data_item in data:
            self.send_block("conf-set", section=section, identifier=identifier, item=item, zone=zone, data=data_item)

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

    # Adds a new DNS zone
    def zone_new(self, domain_name: str) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.set_item(section="zone", item="domain", data=domain_name)
            resp = self.receive_block()
        except Exception as e:
            raise KnotInternalError(str(e))
        return resp

    # Removes a DNS zone
    def zone_remove(self, domain_name: str) -> JsonNodeT:
        if not self.connected:
            raise KnotApiError("Knot socket is closed")

        try:
            self.send_block("conf-unset", section="zone", item="domain", zone=domain_name)
            resp = self.receive_block()
        except Exception as e:
            raise KnotInternalError(str(e))
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


def knot_connect(transaction_opts: Optional[JsonNodeT]):
    debug_knot("Connecting to KNOT socket")
    KNOT.knot_connect()

    if transaction_opts in ("config", None):
        debug_knot("Starting new KNOT config transaction")
        KNOT.begin()
    elif transaction_opts == "zone":
        debug_knot("Starting new KNOT zone transaction")
        KNOT.begin_zone()


def knot_disconnect(transaction_opts: Optional[JsonNodeT]):
    if transaction_opts in ("config", None):
        debug_knot("Commiting KNOT config transaction")
        KNOT.commit()
    elif transaction_opts == "zone":
        debug_knot("Commiting KNOT zone transaction")
        KNOT.commit_zone()

    debug_knot("Disonnecting from KNOT socket")
    KNOT.knot_disconnect()


def knot_api_init():
    global KNOT
    if KNOT is None:
        KNOT = KnotConfig(CONFIG["KNOT"]["SOCKET"])
    else:
        raise ValueError("Knot API already instantiated")
