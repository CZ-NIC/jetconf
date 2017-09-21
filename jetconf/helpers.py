import logging

from colorlog import debug, getLogger
from enum import Enum
from typing import List, Dict, Union, Any, Iterable
from datetime import datetime
from pytz import timezone

from yangson.instance import InstanceRoute, MemberName, EntryKeys, InstanceNode, ArrayValue, NonexistentInstance
from yangson.schemanode import ListNode, ContainerNode

from . import config

JsonNodeT = Union[Dict[str, Any], List]
SSLCertT = Dict[str, Any]


class PathFormat(Enum):
    URL = 0
    XPATH = 1


class CertHelpers:
    @staticmethod
    def get_field(cert: SSLCertT, key: str) -> str:
        if config.CFG.http["DBG_DISABLE_CERTS"] and (key == "emailAddress"):
            return "test-user"

        try:
            retval = ([x[0][1] for x in cert["subject"] if x[0][0] == key] or [None])[0]
        except (IndexError, KeyError, TypeError):
            retval = None
        return retval


class DataHelpers:
    # Get the namespace of the first segment in path
    # Raises ValueError if the first segment is not in fully-qualified format
    # Returns empty string if api_pth is empty
    # @staticmethod
    # def path_first_ns(api_pth: str) -> str:
    #     if (len(api_pth) > 0) and (api_pth[0] == "/"):
    #         first_seg = api_pth[1:].split("/", maxsplit=1)[0]
    #         ns1, sel1 = first_seg.split(":", maxsplit=1)
    #     else:
    #         ns1 = ""
    #     return ns1

    # Convert InstanceRoute or List[InstanceSelector] to string
    @staticmethod
    def ii2str(ii: Iterable) -> str:
        return "".join([str(seg) for seg in ii])

    @staticmethod
    def node_get_ii(node: InstanceNode) -> InstanceRoute:
        m = node
        ii_gen = InstanceRoute()
        try:
            while m:
                m_sn = m.schema_node
                m_sn_dp = m_sn.data_parent()

                if isinstance(m_sn, ListNode):
                    if isinstance(m.value, ArrayValue):
                        mn = MemberName(m_sn.qual_name[0], None if m_sn_dp and m_sn.ns == m_sn_dp.ns else m_sn.qual_name[1])
                        ii_gen.append(mn)
                    else:
                        kv = {}
                        for qk in m_sn.keys:
                            k = qk[0]
                            k_ns = None if m_sn_dp and m_sn.ns == m_sn_dp.ns else qk[1]
                            kv[(k, k_ns)] = m.value.get(k)
                        ek = EntryKeys(kv)
                        ii_gen.append(ek)
                elif isinstance(m_sn, ContainerNode):
                    mn = MemberName(m_sn.qual_name[0], None if m_sn_dp and m_sn.ns == m_sn_dp.ns else m_sn.qual_name[1])
                    ii_gen.append(mn)
                m = m.up()
        except NonexistentInstance:
            pass

        ii_gen.reverse()
        return ii_gen


class DateTimeHelpers:
    @staticmethod
    def to_httpdate_str(dt: datetime, local_tz: str=None) -> str:
        if local_tz is not None:
            dtl = timezone(local_tz).localize(dt)
            dt_gmt = dtl.astimezone(timezone("GMT"))
        else:
            dt_gmt = dt

        return dt_gmt.strftime("%a, %d %b %Y %H:%M:%S GMT")


class ErrorHelpers:
    @staticmethod
    def epretty(e: BaseException, module_name: str=None) -> str:
        err_str = e.__class__.__name__ + ": " + str(e)
        if module_name is not None:
            return "In module " + module_name + ": " + err_str
        else:
            return err_str


class LogHelpers:
    @staticmethod
    def create_module_dbg_logger(module_name: str):
        module_name_simple = module_name.split(".")[-1]

        def module_dbg_logger(msg: str):
            if ({module_name_simple, "*"} & set(config.CFG.glob["LOG_DBG_MODULES"])) and (config.CFG.glob["LOG_LEVEL"] == "debug"):
                logger = getLogger()
                logger.setLevel(logging.DEBUG)
                debug(module_name_simple + ": " + msg)
                logger.setLevel(logging.INFO)

        return module_dbg_logger
