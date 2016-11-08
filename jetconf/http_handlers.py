import json
import os
import mimetypes

from collections import OrderedDict
from enum import Enum
from colorlog import error, warning as warn, info
from urllib.parse import parse_qs
from typing import Dict, List, Optional

from yangson.schema import NonexistentSchemaNode
from yangson.instance import NonexistentInstance, InstanceValueError
from yangson.datatype import YangTypeError

from .knot_api import KnotError
from .config import CONFIG_GLOBAL, CONFIG_HTTP, NACM_ADMINS, API_ROOT_data, API_ROOT_STAGING_data, API_ROOT_ops
from .helpers import CertHelpers, DataHelpers, DateTimeHelpers, ErrorHelpers, LogHelpers, SSLCertT
from .data import (
    BaseDatastore,
    RpcInfo,
    DataLockError,
    NacmForbiddenError,
    NoHandlerError,
    NoHandlerForOpError,
    InstanceAlreadyPresent,
    ChangeType
)

QueryStrT = Dict[str, List[str]]
epretty = ErrorHelpers.epretty
debug_httph = LogHelpers.create_module_dbg_logger(__name__)


CT_PLAIN = "text/plain"
CT_YANG_JSON = "application/yang.api+json"


class HttpStatus(Enum):
    Ok          = ("200", "OK")
    Created     = ("201", "Created")
    NoContent   = ("204", "No Content")
    BadRequest  = ("400", "Bad Request")
    Forbidden   = ("403", "Forbidden")
    NotFound    = ("404", "Not Found")
    MethodNotAllowed    = ("405", "Method Not Allowed")
    NotAcceptable       = ("406", "Not Acceptable")
    Conflict    = ("409", "Conflict")
    InternalServerError = ("500", "Internal Server Error")

    @property
    def code(self) -> str:
        return self.value[0]

    @property
    def msg(self) -> str:
        return self.value[1]


class HttpResponse:
    def __init__(self, status: HttpStatus, data: bytes, content_type: str, extra_headers: OrderedDict=None):
        self.status_code = status.code
        self.data = data
        self.content_type = content_type
        self.extra_headers = extra_headers

    @classmethod
    def empty(cls, status: HttpStatus, status_in_body: bool=True) -> "HttpResponse":
        if status_in_body:
            response = status.code + " " + status.msg + "\n"
        else:
            response = ""

        return cls(status, response.encode(), CT_PLAIN)


def unknown_req_handler(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
    return HttpResponse.empty(HttpStatus.BadRequest)


def api_root_handler(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT):
    # Top level api resource (appendix D.1.1)
    response = (
        "{\n"
        "    \"ietf-restconf:restconf\": {\n"
        "        \"data\" : [ null ],\n"
        "        \"operations\" : [ null ]\n"
        "    }\n"
        "}"
    )

    return HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON)


def _get(ds: BaseDatastore, pth: str, username: str, yl_data: bool=False, staging: bool=False) -> HttpResponse:
    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path
    rpc1.qs = query_string

    try:
        ds.lock_data(username)
        n = ds.get_node_rpc(rpc1, yl_data, staging)
        ds.unlock_data()

        response = json.dumps(n.raw_value(), indent=4)

        add_headers = OrderedDict()
        add_headers["ETag"] = hash(n.value)
        try:
            lm_time = DateTimeHelpers.to_httpdate_str(n.value.timestamp, CONFIG_GLOBAL["TIMEZONE"])
            add_headers["Last-Modified"] = lm_time
        except AttributeError:
            # Only arrays and objects have last_modified attribute
            pass

        http_resp = HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON, extra_headers=add_headers)
    except DataLockError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.InternalServerError)
    except NacmForbiddenError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.Forbidden)
    except (NonexistentSchemaNode, NonexistentInstance) as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.NotFound)
    except InstanceValueError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.BadRequest)
    except KnotError as e:
        error(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.InternalServerError)

    return http_resp


def create_get_api(ds: BaseDatastore):
    def get_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_get: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                http_resp = HttpResponse.empty(HttpStatus.Forbidden)
            else:
                http_resp = _get(ds.nacm.nacm_ds, username, api_pth)
        elif ns == "ietf-yang-library":
            http_resp = _get(ds, api_pth, username, yl_data=True)
        else:
            http_resp = _get(ds, api_pth, username)

        return http_resp

    return get_api_closure


def create_get_staging_api(ds: BaseDatastore):
    def get_staging_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_get_staging: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_STAGING_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                http_resp = HttpResponse.empty(HttpStatus.Forbidden)
            else:
                http_resp = _get(ds.nacm.nacm_ds, username, api_pth, staging=True)
        else:
            http_resp = _get(ds, username, api_pth, staging=True)

        return http_resp

    return get_staging_api_closure


def get_file(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
    # Ordinary file on filesystem
    username = CertHelpers.get_field(client_cert, "emailAddress")
    url_path = headers[":path"].split("?")[0]
    url_path_safe = "".join(filter(lambda c: c.isalpha() or c in "/-_.", url_path)).replace("..", "").strip("/")
    file_path = os.path.join(CONFIG_HTTP["DOC_ROOT"], url_path_safe)

    if os.path.isdir(file_path):
        file_path = os.path.join(file_path, CONFIG_HTTP["DOC_DEFAULT_NAME"])

    ctype = mimetypes.guess_type(file_path)[0] or "application/octet-stream"

    try:
        fd = open(file_path, 'rb')
        response = fd.read()
        fd.close()
    except FileNotFoundError:
        warn("[{}] Cannot open requested file \"{}\"".format(username, file_path))
        http_resp = HttpResponse.empty(HttpStatus.NotFound)
    else:
        info("[{}] Serving ordinary file {} of type \"{}\"".format(username, file_path, ctype))
        http_resp = HttpResponse(HttpStatus.Ok, response, ctype)

    return http_resp


def _post(ds: BaseDatastore, pth: str, username: str, data: str) -> HttpResponse:
    debug_httph("HTTP data received: " + data)

    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path
    rpc1.qs = query_string

    try:
        json_data = json.loads(data) if len(data) > 0 else {}
    except ValueError as e:
        error("Failed to parse POST data: " + epretty(e))
        return HttpResponse.empty(HttpStatus.BadRequest)

    try:
        ds.lock_data(username)
        new_root = ds.create_node_rpc(ds.get_data_root_staging(rpc1.username), rpc1, json_data)
        ds.add_to_journal_rpc(ChangeType.CREATE, rpc1, json_data, new_root)
        http_resp = HttpResponse.empty(HttpStatus.Created)
    except DataLockError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.InternalServerError)
    except NacmForbiddenError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.Forbidden)
    except (NonexistentSchemaNode, NonexistentInstance) as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.NotFound)
    except (InstanceValueError, YangTypeError, NoHandlerError, ValueError) as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.BadRequest)
    except InstanceAlreadyPresent as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.Conflict)
    finally:
        ds.unlock_data()

    return http_resp


def create_post_api(ds: BaseDatastore):
    def post_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_post: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                http_resp = HttpResponse.empty(HttpStatus.Forbidden)
            else:
                http_resp = _post(ds.nacm.nacm_ds, api_pth, username, data)
                ds.nacm.update()
        else:
            http_resp = _post(ds, api_pth, username, data)

        return http_resp

    return post_api_closure


def _put(ds: BaseDatastore, pth: str, username: str, data: str) -> HttpResponse:
    debug_httph("HTTP data received: " + data)

    url_split = pth.split("?")
    url_path = url_split[0]

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path

    try:
        json_data = json.loads(data) if len(data) > 0 else {}
    except ValueError as e:
        error("Failed to parse PUT data: " + epretty(e))
        return HttpResponse.empty(HttpStatus.BadRequest)

    try:
        ds.lock_data(username)
        new_root = ds.update_node_rpc(ds.get_data_root_staging(rpc1.username), rpc1, json_data)
        ds.add_to_journal_rpc(ChangeType.REPLACE, rpc1, json_data, new_root)
        http_resp = HttpResponse.empty(HttpStatus.NoContent, status_in_body=False)
    except DataLockError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.InternalServerError)
    except NacmForbiddenError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.Forbidden)
    except (NonexistentSchemaNode, NonexistentInstance) as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.NotFound)
    except NoHandlerError as e:
        warn(epretty(e))
        http_resp = HttpResponse.empty(HttpStatus.BadRequest)
    finally:
        ds.unlock_data()

    return http_resp


def create_put_api(ds: BaseDatastore):
    def put_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_put: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                http_resp = HttpResponse.empty(HttpStatus.Forbidden)
            else:
                http_resp = _put(ds.nacm.nacm_ds, api_pth, username, data)
                ds.nacm.update()
        else:
            http_resp = _put(ds, api_pth, username, data)

        return http_resp

    return put_api_closure


def _delete(ds: BaseDatastore, pth: str, username: str) -> HttpResponse:
        url_split = pth.split("?")
        url_path = url_split[0]

        rpc1 = RpcInfo()
        rpc1.username = username
        rpc1.path = url_path

        try:
            ds.lock_data(username)
            new_root = ds.delete_node_rpc(ds.get_data_root_staging(rpc1.username), rpc1)
            ds.add_to_journal_rpc(ChangeType.DELETE, rpc1, None, new_root)
            http_resp = HttpResponse.empty(HttpStatus.NoContent, status_in_body=False)
        except DataLockError as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.InternalServerError)
        except NacmForbiddenError as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.Forbidden)
        except (NonexistentSchemaNode, NonexistentInstance) as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.NotFound)
        except NoHandlerError as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.BadRequest)
        finally:
            ds.unlock_data()

        return http_resp


def create_api_delete(ds: BaseDatastore):
    def api_delete_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_delete: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                http_resp = HttpResponse.empty(HttpStatus.Forbidden)
            else:
                http_resp = _delete(ds.nacm.nacm_ds, api_pth, username)
                ds.nacm.update()
        else:
            http_resp = _delete(ds, api_pth, username)

        return http_resp

    return api_delete_closure


def create_api_op(ds: BaseDatastore):
    def api_op_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] invoke_op: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_ops):]
        op_name_fq = api_pth[1:]
        op_name_splitted = op_name_fq.split(":", maxsplit=1)

        try:
            ns = op_name_splitted[0]
            op_name = op_name_splitted[1]
        except IndexError:
            warn("Operation name must be in fully-qualified format")
            return HttpResponse.empty(HttpStatus.BadRequest)

        try:
            json_data = json.loads(data) if len(data) > 0 else {}
        except ValueError as e:
            error("Failed to parse POST data: " + epretty(e))
            return HttpResponse.empty(HttpStatus.BadRequest)

        input_args = json_data.get(ns + ":input")

        rpc1 = RpcInfo()
        rpc1.username = username
        rpc1.path = api_pth
        rpc1.op_name = op_name
        rpc1.op_input_args = input_args

        # Skip NACM check for privileged users
        if username in NACM_ADMINS:
            rpc1.skip_nacm_check = True

        try:
            ret_data = ds.invoke_op_rpc(rpc1)
            if ret_data is None:
                http_resp = HttpResponse.empty(HttpStatus.NoContent, status_in_body=False)
            else:
                response = json.dumps(ret_data, indent=4)
                http_resp = HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON)
        except NacmForbiddenError as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.Forbidden)
        except NonexistentSchemaNode as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.NotFound)
        except (InstanceAlreadyPresent, NoHandlerForOpError, ValueError) as e:
            warn(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.BadRequest)
        except KnotError as e:
            error(epretty(e))
            http_resp = HttpResponse.empty(HttpStatus.InternalServerError)

        return http_resp

    return api_op_closure
