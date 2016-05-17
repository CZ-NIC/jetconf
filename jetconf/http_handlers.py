import json
import os
import mimetypes
from collections import OrderedDict
from colorlog import error, warning as warn, info, debug
from urllib.parse import parse_qs
from typing import Dict, List

from yangson.schema import NonexistentSchemaNode
from yangson.instance import NonexistentInstance, InstanceTypeError, DuplicateMember

from .config import CONFIG_GLOBAL, CONFIG_HTTP, NACM_ADMINS, API_ROOT_data, API_ROOT_ops
from .helpers import CertHelpers, DataHelpers, DateTimeHelpers, ErrorHelpers
from .data import BaseDatastore, RpcInfo, DataLockError, NacmForbiddenError, NoHandlerForOpError, InstanceAlreadyPresent, ChangeType

QueryStrT = Dict[str, List[str]]
epretty = ErrorHelpers.epretty


def unknown_req_handler(prot: "H2Protocol", stream_id: int, headers: OrderedDict, data: bytes=None):
    prot.send_empty(stream_id, "400", "Bad Request")


def api_root_handler(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
    # Top level api resource (appendix D.1.1)
    response_bytes = (
        "{\n"
        "    \"ietf-restconf:restconf\": {\n"
        "        \"data\" : [ null ],\n"
        "        \"operations\" : [ null ]\n"
        "    }\n"
        "}"
    ).encode()

    response_headers = (
        (':status', '200'),
        ('content-type', 'application/yang.api+json'),
        ('content-length', len(response_bytes)),
        ('server', CONFIG_HTTP["SERVER_NAME"]),
    )

    prot.conn.send_headers(stream_id, response_headers)
    prot.conn.send_data(stream_id, response_bytes, end_stream=True)


def _get(prot: "H2Protocol", stream_id: int, ds: BaseDatastore, pth: str):
    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

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
        n = ds.get_node_rpc(rpc1)

        response = json.dumps(n.value, indent=4) + "\n"
        response_bytes = response.encode()

        response_headers = [
            (":status", "200"),
            ("server", CONFIG_HTTP["SERVER_NAME"])
        ]
        try:
            lm_time = DateTimeHelpers.to_httpdate_str(n.value.last_modified, CONFIG_GLOBAL["TIMEZONE"])
            response_headers.append(("Last-Modified", lm_time))
        except AttributeError:
            # Only arrays and objects have last_modified attribute
            pass
        response_headers.append(("ETag", hash(n.value)))
        response_headers.append(("Content-Type", "application/yang.api+json"))
        response_headers.append(("content-length", len(response_bytes)))

        prot.conn.send_headers(stream_id, response_headers)
        prot.conn.send_data(stream_id, response_bytes, end_stream=True)
    except DataLockError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "500", "Internal Server Error")
    except NacmForbiddenError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "403", "Forbidden")
    except NonexistentSchemaNode as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "404", "Not Found")
    except NonexistentInstance as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "404", "Not Found")
    except InstanceTypeError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "400", "Bad Request")
    finally:
        ds.unlock_data()


def create_get_api(ds: BaseDatastore):
    def get_api_closure(prot: "H2Protocol", stream_id: int, headers: OrderedDict):
        # api request
        info(("api_get: " + headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            username = CertHelpers.get_field(prot.client_cert, "emailAddress")
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                prot.send_empty(stream_id, "403", "Forbidden")
            else:
                _get(prot, stream_id, ds.nacm.nacm_ds, api_pth)
        else:
            _get(prot, stream_id, ds, api_pth)

    return get_api_closure


def get_file(prot: "H2Protocol", stream_id: int, headers: OrderedDict):
    # Ordinary file on filesystem

    url_split = headers[":path"].split("?")
    url_path = url_split[0]

    file_path = os.path.join(CONFIG_HTTP["DOC_ROOT"], url_path[1:].replace("..", "").replace("&", ""))

    if os.path.isdir(file_path):
        file_path = os.path.join(file_path, CONFIG_HTTP["DOC_DEFAULT_NAME"])

    (ctype, encoding) = mimetypes.guess_type(file_path)
    if ctype is None:
        ctype = "application/octet-stream"

    try:
        fd = open(file_path, 'rb')
        response = fd.read()
        fd.close()
    except FileNotFoundError:
        warn("Cannot open requested file \"{}\"".format(file_path))
        response_headers = (
            (':status', '404'),
            ('content-length', 0),
            ('server', CONFIG_HTTP["SERVER_NAME"]),
        )
        prot.conn.send_headers(stream_id, response_headers, end_stream=True)
        return

    info("Serving ordinary file {} of type \"{}\"".format(file_path, ctype))
    response_headers = (
        (':status', '200'),
        ('content-type', ctype),
        ('content-length', len(response)),
        ('server', CONFIG_HTTP["SERVER_NAME"]),
    )
    prot.conn.send_headers(stream_id, response_headers)

    def split_arr(arr, chunk_size):
        for i in range(0, len(arr), chunk_size):
            yield arr[i:i + chunk_size]

    for data_chunk in split_arr(response, prot.conn.max_outbound_frame_size):
        prot.conn.send_data(stream_id, data_chunk, end_stream=False)

    prot.conn.send_data(stream_id, bytes(), end_stream=True)


def _post(prot: "H2Protocol", data: bytes, stream_id: int, ds: BaseDatastore, pth: str):
    data_str = data.decode("utf-8")
    debug("HTTP data received: " + data_str)

    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path

    try:
        json_data = json.loads(data_str)
    except ValueError as e:
        error("Invalid HTTP data: " + str(e))
        prot.send_empty(stream_id, "400", "Bad Request")
        return

    try:
        ds.lock_data(username)
        ins_pos = (query_string.get("insert") or [None])[0]
        point = (query_string.get("point") or [None])[0]
        # ds.create_node_rpc(rpc1, json_data, insert=ins_pos, point=point)
        ds.add_to_journal_rpc(ChangeType.CREATE, rpc1, json_data)
        prot.send_empty(stream_id, "201", "Created")
    except DataLockError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "500", "Internal Server Error")
    except NacmForbiddenError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "403", "Forbidden")
    except NonexistentSchemaNode as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "404", "Not Found")
    except NonexistentInstance as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "404", "Not Found")
    except DuplicateMember as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "409", "Conflict")
    except InstanceTypeError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "400", "Bad Request")
    except InstanceAlreadyPresent as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "400", "Bad Request")
    finally:
        ds.unlock_data()


def create_post_api(ds: BaseDatastore):
    def post_api_closure(prot: "H2Protocol", stream_id: int, headers: OrderedDict, data: bytes):
        info(("api_post: " + headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            username = CertHelpers.get_field(prot.client_cert, "emailAddress")
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                prot.send_empty(stream_id, "403", "Forbidden")
            else:
                _post(prot, data, stream_id, ds.nacm.nacm_ds, api_pth)
                ds.nacm.update()
        else:
            _post(prot, data, stream_id, ds, api_pth)

    return post_api_closure


def _put(prot: "H2Protocol", data: bytes, stream_id: int, ds: BaseDatastore, pth: str):
    data_str = data.decode("utf-8")
    debug("HTTP data received: " + data_str)

    url_split = pth.split("?")
    url_path = url_split[0]

    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

    rpc1 = RpcInfo()
    rpc1.username = username
    rpc1.path = url_path

    json_data = json.loads(data_str)

    try:
        ds.lock_data(username)
        # ds.update_node_rpc(rpc1, json_data)
        ds.add_to_journal_rpc(ChangeType.REPLACE, rpc1, json_data)
        prot.send_empty(stream_id, "204", "No Content", False)
    except DataLockError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "500", "Internal Server Error")
    except NacmForbiddenError as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "403", "Forbidden")
    except NonexistentSchemaNode as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "404", "Not Found")
    except NonexistentInstance as e:
        warn(epretty(e))
        prot.send_empty(stream_id, "404", "Not Found")
    finally:
        ds.unlock_data()


def create_put_api(ds: BaseDatastore):
    def put_api_closure(prot: "H2Protocol", stream_id: int, headers: OrderedDict, data: bytes):
        info(("api_put: " + headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            username = CertHelpers.get_field(prot.client_cert, "emailAddress")
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                prot.send_empty(stream_id, "403", "Forbidden")
            else:
                _put(prot, data, stream_id, ds.nacm.nacm_ds, api_pth)
                ds.nacm.update()
        else:
            _put(prot, data, stream_id, ds, api_pth)

    return put_api_closure


def _delete(prot: "H2Protocol", stream_id: int, ds: BaseDatastore, pth: str):
        url_split = pth.split("?")
        url_path = url_split[0]

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")

        rpc1 = RpcInfo()
        rpc1.username = username
        rpc1.path = url_path

        try:
            ds.lock_data(username)
            # ds.delete_node_rpc(rpc1)
            ds.add_to_journal_rpc(ChangeType.DELETE, rpc1, None)
            prot.send_empty(stream_id, "204", "No Content", False)
        except DataLockError as e:
            warn(epretty(e))
            prot.send_empty(stream_id, "500", "Internal Server Error")
        except NacmForbiddenError as e:
            warn(epretty(e))
            prot.send_empty(stream_id, "403", "Forbidden")
        except NonexistentSchemaNode as e:
            warn(epretty(e))
            prot.send_empty(stream_id, "404", "Not Found")
        except NonexistentInstance as e:
            warn(epretty(e))
            prot.send_empty(stream_id, "404", "Not Found")
        finally:
            ds.unlock_data()


def create_api_delete(ds: BaseDatastore):
    def api_delete_closure(prot: "H2Protocol", stream_id: int, headers: OrderedDict):
        info(("api_delete: " + headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        ns = DataHelpers.path_first_ns(api_pth)

        if ns == "ietf-netconf-acm":
            username = CertHelpers.get_field(prot.client_cert, "emailAddress")
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                prot.send_empty(stream_id, "403", "Forbidden")
            else:
                _delete(prot, stream_id, ds.nacm.nacm_ds, api_pth)
                ds.nacm.update()
        else:
            _delete(prot, stream_id, ds, api_pth)

    return api_delete_closure


def create_api_op(ds: BaseDatastore):
    def api_op_closure(prot: "H2Protocol", stream_id: int, headers: OrderedDict, data: bytes):
        info("invoke_op: " + headers[":path"])
        data_str = data.decode("utf-8")

        api_pth = headers[":path"][len(API_ROOT_ops):]
        op_name_fq = api_pth[1:]
        op_name_splitted = op_name_fq.split(":", maxsplit=1)

        if len(op_name_splitted) < 2:
            warn("Operation name must be in fully-qualified format")
            prot.send_empty(stream_id, "400", "Bad Request")
            return

        ns = op_name_splitted[0]
        op_name = op_name_splitted[1]

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")

        try:
            json_data = json.loads(data_str)
        except ValueError as e:
            error("Invalid HTTP data: " + str(e))
            prot.send_empty(stream_id, "400", "Bad Request")
            return

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
                prot.send_empty(stream_id, "204", "No Content", False)
            else:
                response = json.dumps(ret_data, indent=4) + "\n"
                response_bytes = response.encode()

                response_headers = (
                    (':status', '200'),
                    ('content-type', 'application/yang.api+json'),
                    ('content-length', len(response_bytes)),
                    ('server', CONFIG_HTTP["SERVER_NAME"]),
                )

                prot.conn.send_headers(stream_id, response_headers)
                prot.conn.send_data(stream_id, response_bytes, end_stream=True)

        except NacmForbiddenError as e:
            warn(epretty(e))
            prot.send_empty(stream_id, "403", "Forbidden")
        except NonexistentSchemaNode as e:
            warn(epretty(e))
            prot.send_empty(stream_id, "404", "Not Found")
        except NoHandlerForOpError:
            warn("Nonexistent handler for operation \"{}\"".format(op_name))
            prot.send_empty(stream_id, "400", "Bad Request")

    return api_op_closure
