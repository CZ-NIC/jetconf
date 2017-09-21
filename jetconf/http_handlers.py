import json
import os
import mimetypes

from collections import OrderedDict
from enum import Enum
from colorlog import error, warning as warn, info
from urllib.parse import parse_qs
from datetime import datetime
from typing import Dict, List, Optional

from yangson.exceptions import YangsonException, NonexistentSchemaNode, SchemaError, SemanticError
from yangson.schemanode import ContainerNode, ListNode, GroupNode, LeafNode
from yangson.instance import NonexistentInstance, InstanceValueError, RootNode

from . import config
from .helpers import CertHelpers, DateTimeHelpers, ErrorHelpers, LogHelpers, SSLCertT
from .handler_list import OP_HANDLERS
from .data import (
    BaseDatastore,
    RpcInfo,
    ChangeType,
)
from .errors import (
    BackendError,
    ConfHandlerFailedError,
    StagingDataException,
    NoHandlerForOpError,
    InstanceAlreadyPresent,
    OpHandlerFailedError,
    NoHandlerError,
    DataLockError,
    NacmForbiddenError
)

QueryStrT = Dict[str, List[str]]
epretty = ErrorHelpers.epretty
debug_httph = LogHelpers.create_module_dbg_logger(__name__)


CT_PLAIN = "text/plain"
CT_YANG_JSON = "application/yang.api+json"


class HttpRequestError(Exception):
    pass


class HttpStatus(Enum):
    Ok          = ("200", "OK")
    Created     = ("201", "Created")
    NoContent   = ("204", "No Content")
    NotModified = ("304", "Not Modified")
    BadRequest  = ("400", "Bad Request")
    Forbidden   = ("403", "Forbidden")
    NotFound    = ("404", "Not Found")
    MethodNotAllowed    = ("405", "Method Not Allowed")
    NotAcceptable       = ("406", "Not Acceptable")
    Conflict    = ("409", "Conflict")
    ReqTooLarge = ("413", "Request Entity Too Large")
    InternalServerError = ("500", "Internal Server Error")

    @property
    def code(self) -> str:
        return self.value[0]

    @property
    def msg(self) -> str:
        return self.value[1]


ERRTAG_MALFORMED = "malformed-message"
ERRTAG_REQLARGE = "request-too-large"
ERRTAG_OPNOTSUPPORTED = "operation-not-supported"
ERRTAG_OPFAILED = "operation-failed"
ERRTAG_ACCDENIED = "access-denied"
ERRTAG_LOCKDENIED = "lock-denied"
ERRTAG_INVVALUE = "invalid-value"
ERRTAG_EXISTS = "data-exists"


class RestconfErrType(Enum):
    Transport   = "transport"
    Rpc         = "rpc"
    Protocol    = "protocol"
    Application = "application"


class HttpResponse:
    def __init__(self, status: HttpStatus, data: bytes, content_type: str, extra_headers: OrderedDict=None):
        self.status_code = status.code
        self.data = data
        self.content_length = len(data)
        self.content_type = content_type
        self.extra_headers = extra_headers

    @classmethod
    def empty(cls, status: HttpStatus, status_in_body: bool=False) -> "HttpResponse":
        if status_in_body:
            response = status.code + " " + status.msg + "\n"
        else:
            response = ""

        return cls(status, response.encode(), CT_PLAIN)

    @classmethod
    def error(cls, status: HttpStatus, err_type: RestconfErrType, err_tag: str, err_apptag: str=None,
              err_path: str=None, err_msg: str=None, exception: Exception=None) -> "HttpResponse":
        err_body = {
            "error-type": err_type.value,
            "error-tag": err_tag
        }

        # Auto-fill app-tag, path and mesage fields from Python's Exception attributes
        if exception is not None:
            try:
                err_body["error-app-tag"] = exception.tag
            except AttributeError:
                pass

            try:
                err_body["error-path"] = exception.path
            except AttributeError:
                pass

            try:
                err_body["error-message"] = exception.__class__.__name__ + ": " + exception.message
            except AttributeError:
                err_body["error-message"] = exception.__class__.__name__ + ": " + str(exception)

        if err_apptag is not None:
            err_body["error-app-tag"] = err_apptag

        if err_path is not None:
            err_body["error-path"] = err_path

        if err_msg is not None:
            err_body["error-message"] = err_msg

        err_template = {
            "ietf-restconf:errors": {
                "error": [
                    err_body
                ]
            }
        }

        response = json.dumps(err_template, indent=4)
        return cls(status, response.encode(), CT_YANG_JSON)


def unknown_req_handler(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
    return HttpResponse.error(
        HttpStatus.BadRequest,
        RestconfErrType.Transport,
        ERRTAG_MALFORMED,
        "unknown_req_handler"
    )


def _get_yl_date() -> str:
    try:
        yang_lib_date_ts = os.path.getmtime(os.path.join(config.CFG.glob["YANG_LIB_DIR"], "yang-library-data.json"))
        yang_lib_date = datetime.fromtimestamp(yang_lib_date_ts).strftime("%Y-%m-%d")
    except OSError:
        yang_lib_date = None

    return yang_lib_date


def api_root_handler(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT):
    # Top level api resource (appendix B.1.1)

    top_res = {
        "ietf-restconf:restconf": {
            "data": {},
            "operations": {},
            "yang-library-version": _get_yl_date()
        }
    }

    response = json.dumps(top_res, indent=4)
    return HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON)


def api_ylv_handler(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT):
    ylv = {
        "ietf-restconf:yang-library-version": _get_yl_date()
    }

    response = json.dumps(ylv, indent=4)
    return HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON)


def _get(ds: BaseDatastore, req_headers: OrderedDict, pth: str, username: str, staging: bool=False) -> HttpResponse:
    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path.rstrip("/")
    rpc1.qs = query_string

    # Skip NACM check for privileged users
    if username in config.CFG.nacm["ALLOWED_USERS"]:
        rpc1.skip_nacm_check = True

    try:
        ds.lock_data(username)
        http_resp = None

        try:
            n = ds.get_node_rpc(rpc1, staging)
        except NacmForbiddenError as e:
            http_resp = HttpResponse.error(
                HttpStatus.Forbidden,
                RestconfErrType.Protocol,
                ERRTAG_ACCDENIED,
                exception=e
            )
        except (NonexistentSchemaNode, NonexistentInstance) as e:
            http_resp = HttpResponse.error(
                HttpStatus.NotFound,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except (InstanceValueError, ValueError) as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except (ConfHandlerFailedError, NoHandlerError, YangsonException, BackendError) as e:
            http_resp = HttpResponse.error(
                HttpStatus.InternalServerError,
                RestconfErrType.Protocol,
                ERRTAG_OPFAILED,
                exception=e
            )
        finally:
            ds.unlock_data()

        if http_resp is not None:
            # Return error response
            return http_resp

        hdr_inm = req_headers.get("if-none-match")
        n_etag = str(hash(n.value))

        if (hdr_inm is not None) and (hdr_inm == n_etag):
            http_resp = HttpResponse.empty(HttpStatus.NotModified)
        else:
            n_value = n.raw_value()

            if isinstance(n, RootNode):
                # Getting top-level node
                restconf_env = "ietf-restconf:data"
                restconf_n_value = {restconf_env: n_value}
            else:
                sn = n.schema_node
                if isinstance(sn, (ContainerNode, GroupNode, LeafNode)):
                    restconf_env = "{}:{}".format(sn.qual_name[1], sn.qual_name[0])
                    restconf_n_value = {restconf_env: n_value}
                elif isinstance(sn, ListNode):
                    restconf_env = "{}:{}".format(sn.qual_name[1], sn.qual_name[0])
                    if isinstance(n_value, list):
                        # List and list item points to the same schema node
                        restconf_n_value = {restconf_env: n_value}
                    else:
                        restconf_n_value = {restconf_env: [n_value]}
                else:
                    raise HttpRequestError()

            response = json.dumps(restconf_n_value, indent=4)

            add_headers = OrderedDict()
            add_headers["ETag"] = n_etag
            try:
                lm_time = DateTimeHelpers.to_httpdate_str(n.value.timestamp, config.CFG.glob["TIMEZONE"])
                add_headers["Last-Modified"] = lm_time
            except AttributeError:
                # Only arrays and objects have last_modified attribute
                pass

            http_resp = HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON, extra_headers=add_headers)

    except DataLockError as e:
        http_resp = HttpResponse.error(
            HttpStatus.Conflict,
            RestconfErrType.Protocol,
            ERRTAG_LOCKDENIED,
            exception=e
        )
    except HttpRequestError as e:
        http_resp = HttpResponse.error(
            HttpStatus.BadRequest,
            RestconfErrType.Protocol,
            ERRTAG_INVVALUE,
            exception=e
        )

    return http_resp


def create_get_api(ds: BaseDatastore):
    def get_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_get: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_data):]
        http_resp = _get(ds, headers, api_pth, username, staging=True)
        return http_resp

    return get_api_closure


def create_get_running_api(ds: BaseDatastore):
    def get_staging_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_get_staging: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_running_data):]
        http_resp = _get(ds, headers, api_pth, username, staging=False)
        return http_resp

    return get_staging_api_closure


def get_file(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
    # Ordinary file on filesystem
    username = CertHelpers.get_field(client_cert, "emailAddress")
    url_path = headers[":path"].split("?")[0]
    url_path_safe = "".join(filter(lambda c: c.isalpha() or c in "/-_.", url_path)).replace("..", "").strip("/")
    file_path = os.path.join(config.CFG.http["DOC_ROOT"], url_path_safe)

    if os.path.isdir(file_path):
        file_path = os.path.join(file_path, config.CFG.http["DOC_DEFAULT_NAME"])

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
    rpc1.path = url_path.rstrip("/")
    rpc1.qs = query_string

    # Skip NACM check for privileged users
    if username in config.CFG.nacm["ALLOWED_USERS"]:
        rpc1.skip_nacm_check = True

    try:
        json_data = json.loads(data) if len(data) > 0 else {}
    except ValueError as e:
        error("Failed to parse POST data: " + epretty(e))
        return HttpResponse.error(
            HttpStatus.BadRequest,
            RestconfErrType.Protocol,
            ERRTAG_INVVALUE,
            exception=e
        )

    try:
        ds.lock_data(username)

        try:
            try:
                staging_root = ds.get_data_root_staging(rpc1.username)
            except StagingDataException:
                info("Starting transaction for user \"{}\"".format(rpc1.username))
                ds.make_user_journal(rpc1.username, None)
                staging_root = ds.get_data_root_staging(rpc1.username)
            new_root = ds.create_node_rpc(staging_root, rpc1, json_data)
            ds.add_to_journal_rpc(ChangeType.CREATE, rpc1, json_data, *new_root)
            http_resp = HttpResponse.empty(HttpStatus.Created)
        except NacmForbiddenError as e:
            http_resp = HttpResponse.error(
                HttpStatus.Forbidden,
                RestconfErrType.Protocol,
                ERRTAG_ACCDENIED,
                exception=e
            )
        except (NonexistentSchemaNode, NonexistentInstance) as e:
            http_resp = HttpResponse.error(
                HttpStatus.NotFound,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except NoHandlerError as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_OPNOTSUPPORTED,
                exception=e
            )
        except (InstanceValueError, YangsonException, ValueError) as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except InstanceAlreadyPresent as e:
            http_resp = HttpResponse.error(
                HttpStatus.Conflict,
                RestconfErrType.Protocol,
                ERRTAG_EXISTS,
                exception=e
            )
    except DataLockError as e:
        http_resp = HttpResponse.error(
            HttpStatus.Conflict,
            RestconfErrType.Protocol,
            ERRTAG_LOCKDENIED,
            exception=e
        )
    finally:
        ds.unlock_data()

    return http_resp


def create_post_api(ds: BaseDatastore):
    def post_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_post: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_data):]
        http_resp = _post(ds, api_pth, username, data)
        return http_resp

    return post_api_closure


def _put(ds: BaseDatastore, pth: str, username: str, data: str) -> HttpResponse:
    debug_httph("HTTP data received: " + data)

    url_split = pth.split("?")
    url_path = url_split[0]

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path.rstrip("/")

    # Skip NACM check for privileged users
    if username in config.CFG.nacm["ALLOWED_USERS"]:
        rpc1.skip_nacm_check = True

    try:
        json_data = json.loads(data) if len(data) > 0 else {}
    except ValueError as e:
        error("Failed to parse PUT data: " + epretty(e))
        return HttpResponse.error(
            HttpStatus.BadRequest,
            RestconfErrType.Protocol,
            ERRTAG_INVVALUE,
            exception=e
        )

    try:
        ds.lock_data(username)

        try:
            try:
                staging_root = ds.get_data_root_staging(rpc1.username)
            except StagingDataException:
                info("Starting transaction for user \"{}\"".format(rpc1.username))
                ds.make_user_journal(rpc1.username, None)
                staging_root = ds.get_data_root_staging(rpc1.username)
            new_root = ds.update_node_rpc(staging_root, rpc1, json_data)
            ds.add_to_journal_rpc(ChangeType.REPLACE, rpc1, json_data, *new_root)
            http_resp = HttpResponse.empty(HttpStatus.NoContent, status_in_body=False)
        except NacmForbiddenError as e:
            http_resp = HttpResponse.error(
                HttpStatus.Forbidden,
                RestconfErrType.Protocol,
                ERRTAG_ACCDENIED,
                exception=e
            )
        except (NonexistentSchemaNode, NonexistentInstance) as e:
            http_resp = HttpResponse.error(
                HttpStatus.NotFound,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except NoHandlerError as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_OPNOTSUPPORTED,
                exception=e
            )
        except (InstanceValueError, StagingDataException, YangsonException, ValueError) as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
    except DataLockError as e:
        http_resp = HttpResponse.error(
            HttpStatus.Conflict,
            RestconfErrType.Protocol,
            ERRTAG_LOCKDENIED,
            exception=e
        )
    finally:
        ds.unlock_data()

    return http_resp


def create_put_api(ds: BaseDatastore):
    def put_api_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_put: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_data):]
        http_resp = _put(ds, api_pth, username, data)
        return http_resp

    return put_api_closure


def _delete(ds: BaseDatastore, pth: str, username: str) -> HttpResponse:
        url_split = pth.split("?")
        url_path = url_split[0]

        rpc1 = RpcInfo()
        rpc1.username = username
        rpc1.path = url_path.rstrip("/")

        # Skip NACM check for privileged users
        if username in config.CFG.nacm["ALLOWED_USERS"]:
            rpc1.skip_nacm_check = True

        try:
            ds.lock_data(username)

            try:
                try:
                    staging_root = ds.get_data_root_staging(rpc1.username)
                except StagingDataException:
                    info("Starting transaction for user \"{}\"".format(rpc1.username))
                    ds.make_user_journal(rpc1.username, None)
                    staging_root = ds.get_data_root_staging(rpc1.username)
                new_root = ds.delete_node_rpc(staging_root, rpc1)
                ds.add_to_journal_rpc(ChangeType.DELETE, rpc1, None, *new_root)
                http_resp = HttpResponse.empty(HttpStatus.NoContent, status_in_body=False)
            except NacmForbiddenError as e:
                http_resp = HttpResponse.error(
                    HttpStatus.Forbidden,
                    RestconfErrType.Protocol,
                    ERRTAG_ACCDENIED,
                    exception=e
                )
            except (NonexistentSchemaNode, NonexistentInstance) as e:
                http_resp = HttpResponse.error(
                    HttpStatus.NotFound,
                    RestconfErrType.Protocol,
                    ERRTAG_INVVALUE,
                    exception=e
                )
            except NoHandlerError as e:
                http_resp = HttpResponse.error(
                    HttpStatus.BadRequest,
                    RestconfErrType.Protocol,
                    ERRTAG_OPNOTSUPPORTED,
                    exception=e
                )
            except (InstanceValueError, StagingDataException, YangsonException) as e:
                http_resp = HttpResponse.error(
                    HttpStatus.BadRequest,
                    RestconfErrType.Protocol,
                    ERRTAG_INVVALUE,
                    exception=e
                )
        except DataLockError as e:
            http_resp = HttpResponse.error(
                HttpStatus.Conflict,
                RestconfErrType.Protocol,
                ERRTAG_LOCKDENIED,
                exception=e
            )
        finally:
            ds.unlock_data()

        return http_resp


def create_api_delete(ds: BaseDatastore):
    def api_delete_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] api_delete: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_data):]
        http_resp = _delete(ds, api_pth, username)
        return http_resp

    return api_delete_closure


def create_api_op(ds: BaseDatastore):
    def api_op_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] invoke_op: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_ops):]
        op_name_fq = api_pth[1:].split("/", maxsplit=1)[0]

        try:
            ns, sel1 = op_name_fq.split(":", maxsplit=1)
        except ValueError:
            return HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_MALFORMED,
                "Operation name must be in fully-qualified format"
            )

        try:
            json_data = json.loads(data) if len(data) > 0 else {}
        except ValueError as e:
            return HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_MALFORMED,
                "Failed to parse POST data: " + epretty(e)
            )

        input_args = json_data.get(ns + ":input")

        rpc1 = RpcInfo()
        rpc1.username = username
        rpc1.path = api_pth
        rpc1.op_name = op_name_fq
        rpc1.op_input_args = input_args

        # Skip NACM check for privileged users
        if username in config.CFG.nacm["ALLOWED_USERS"]:
            rpc1.skip_nacm_check = True

        try:
            ret_data = ds.invoke_op_rpc(rpc1)
            if ret_data is None:
                http_resp = HttpResponse.empty(HttpStatus.NoContent, status_in_body=False)
            else:
                if not isinstance(ret_data, str):
                    response = json.dumps(ret_data, indent=4)
                else:
                    response = ret_data
                http_resp = HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON)
        except NacmForbiddenError as e:
            http_resp = HttpResponse.error(
                HttpStatus.Forbidden,
                RestconfErrType.Protocol,
                ERRTAG_ACCDENIED,
                exception=e
            )
        except (NonexistentSchemaNode, NonexistentInstance) as e:
            http_resp = HttpResponse.error(
                HttpStatus.NotFound,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except InstanceAlreadyPresent as e:
            http_resp = HttpResponse.error(
                HttpStatus.Conflict,
                RestconfErrType.Protocol,
                ERRTAG_EXISTS,
                exception=e
            )
        except NoHandlerForOpError as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_OPNOTSUPPORTED,
                exception=e
            )
        except (SchemaError, SemanticError) as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )
        except (ConfHandlerFailedError, OpHandlerFailedError, StagingDataException, YangsonException) as e:
            http_resp = HttpResponse.error(
                HttpStatus.InternalServerError,
                RestconfErrType.Protocol,
                ERRTAG_OPFAILED,
                exception=e
            )
        except ValueError as e:
            http_resp = HttpResponse.error(
                HttpStatus.BadRequest,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                exception=e
            )

        return http_resp

    return api_op_closure


def create_api_get_op(ds: BaseDatastore):
    def api_op_closure(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
        username = CertHelpers.get_field(client_cert, "emailAddress")
        info("[{}] get_op: {}".format(username, headers[":path"]))

        api_pth = headers[":path"][len(config.CFG.api_root_ops):].rstrip("/")
        op_name_fq = api_pth[1:].split("/", maxsplit=1)[0]

        op_names_dict = dict(map(lambda n: (n[0], None), OP_HANDLERS.handlers))

        if api_pth == "":
            # GET root
            ret_data = {
                "ietf-restconf:operations": op_names_dict
            }
        else:
            # GET particular operation
            try:
                ns, op_name = op_name_fq.split(":", maxsplit=1)
            except ValueError:
                return HttpResponse.error(
                    HttpStatus.BadRequest,
                    RestconfErrType.Protocol,
                    ERRTAG_MALFORMED,
                    "Operation name must be in fully-qualified format"
                )

            if op_names_dict.get(op_name_fq, -1) != -1:
                ret_data = {
                    op_name_fq: None
                }
            else:
                # Not found
                ret_data = None

        if ret_data is None:
            http_resp = HttpResponse.error(
                HttpStatus.NotFound,
                RestconfErrType.Protocol,
                ERRTAG_INVVALUE,
                err_path=api_pth,
                err_msg="Operation name not found"
            )
        else:
            response = json.dumps(ret_data, indent=4)
            http_resp = HttpResponse(HttpStatus.Ok, response.encode(), CT_YANG_JSON)

        return http_resp

    return api_op_closure


def options_api(headers: OrderedDict, data: Optional[str], client_cert: SSLCertT) -> HttpResponse:
    info("api_options: {}".format(headers[":path"]))
    headers_extra = OrderedDict()
    headers_extra["Allow"] = "GET, PUT, POST, OPTIONS, HEAD, DELETE"
    http_resp = HttpResponse(HttpStatus.Ok, bytes(), CT_PLAIN, extra_headers=headers_extra)

    return http_resp

