import json
import os
import mimetypes
from collections import OrderedDict
from colorlog import error, warning as warn, info, debug
from urllib.parse import parse_qs
from typing import Dict, List

from yangson.schema import NonexistentSchemaNode
from yangson.instance import NonexistentInstance, InstanceTypeError

from .config import CONFIG_HTTP, NACM_ADMINS, API_ROOT_data, NACM_API_ROOT_data
from .helpers import CertHelpers
from .data import BaseDatastore, Rpc, DataLockError, NacmForbiddenError, InstanceAlreadyPresent

QueryStrT = Dict[str, List[str]]


def api_root_handler(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
    # Top level api resource (appendix D.1.1)
    response = (
        "{\n"
        "    \"ietf-restconf:restconf\": {\n"
        "        \"data\" : [ null ],\n"
        "        \"operations\" : [ null ]\n"
        "    }\n"
        "}"
    )
    response_headers = (
        (':status', '200'),
        ('content-type', 'application/yang.api+json'),
        ('content-length', len(response)),
        ('server', CONFIG_HTTP["SERVER_NAME"]),
    )
    prot.conn.send_headers(stream_id, response_headers)
    prot.conn.send_data(stream_id, response.encode(), end_stream=True)


def get(prot: "H2Protocol", stream_id: int, ds: BaseDatastore, pth: str):
    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    rpc1 = Rpc()
    rpc1.username = username
    rpc1.path = url_path
    rpc1.qs = query_string

    try:
        ds.lock_data(username)
        n = ds.get_node_rpc(rpc1)
        response = json.dumps(n.value, indent=4)
        http_status = "200"
    except DataLockError as e:
        warn(e.msg)
        response = "Internal Server Error"
        http_status = "500"
    except NacmForbiddenError as e:
        warn(e.msg)
        response = "Forbidden"
        http_status = "403"
    except NonexistentSchemaNode:
        warn("NonexistentSchemaNode: " + pth)
        response = "NonexistentSchemaNode"
        http_status = "404"
    except NonexistentInstance:
        warn("NonexistentInstance: " + pth)
        response = "NonexistentInstance"
        http_status = "404"
    except InstanceTypeError:
        warn("InstanceTypeError: " + pth)
        response = "InstanceTypeError"
        http_status = "404"
    finally:
        ds.unlock_data()

    response += "\n"
    response_headers = (
        (':status', http_status),
        ('content-type', 'application/yang.api+json'),
        ('content-length', len(response)),
        ('server', CONFIG_HTTP["SERVER_NAME"]),
    )

    prot.conn.send_headers(stream_id, response_headers)
    prot.conn.send_data(stream_id, response.encode(), end_stream=True)


def create_get_nacm_api(ds: BaseDatastore):
    def get_nacm_api_closure(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
        # NACM api request
        info(("nacm_api_get: " + headers[":path"]))

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")
        if username not in NACM_ADMINS:
            warn(username + " not allowed to access NACM data")
            response = "Forbidden"
            http_status = "403"

            response += "\n"
            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG_HTTP["SERVER_NAME"]),
            )

            prot.conn.send_headers(stream_id, response_headers)
            prot.conn.send_data(stream_id, response.encode(), end_stream=True)
        else:
            api_pth = headers[":path"][len(NACM_API_ROOT_data):]
            get(prot, stream_id, ds.nacm.nacm_ds, api_pth)

    return get_nacm_api_closure


def create_get_api(ds: BaseDatastore):
    def get_api_closure(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
        # api request
        info(("api_get: " + headers[":path"]))

        api_pth = headers[":path"][len(API_ROOT_data):]
        get(prot, stream_id, ds, api_pth)

    return get_api_closure


def get_file(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
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


def post(prot: "H2Protocol", data: bytes, stream_id: int, ds: BaseDatastore, pth: str):
    data_str = data.decode("utf-8")
    info("prijato: " + data_str)

    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    info("qs = {}".format(query_string))

    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

    rpc1 = Rpc()
    rpc1.username = username
    rpc1.path = url_path

    json_data = json.loads(data_str)

    try:
        ds.lock_data(username)
        # ds.nacm.nacm_ds.put_node_rpc(rpc1, json_data)
        ins_pos = (query_string.get("insert") or [None])[0]
        ds.create_node_rpc(rpc1, json_data, insert=ins_pos)
        response = "Done\n"
        http_status = "200"
    except DataLockError as e:
        warn(e.msg)
        response = "Internal Server Error"
        http_status = "500"
    except NacmForbiddenError as e:
        warn(e.msg)
        response = "Forbidden"
        http_status = "403"
    except NonexistentSchemaNode:
        warn("NonexistentSchemaNode: " + pth)
        response = "NonexistentSchemaNode"
        http_status = "404"
    except NonexistentInstance:
        warn("NonexistentInstance: " + pth)
        response = "NonexistentInstance"
        http_status = "404"
    except InstanceAlreadyPresent:
        warn("InstanceAlreadyPresent: " + pth)
        response = "Conflict"
        http_status = "409"
    finally:
        ds.unlock_data()

    response += "\n"
    response = response.encode()
    response_headers = (
        (':status', http_status),
        ('content-type', 'application/yang.api+json'),
        ('content-length', len(response)),
        ('server', CONFIG_HTTP["SERVER_NAME"]),
    )

    prot.conn.send_headers(stream_id, response_headers)
    prot.conn.send_data(stream_id, response, end_stream=True)


def create_post_nacm_api(ds: BaseDatastore):
    def post_nacm_api_closure(prot: "H2Protocol", headers: OrderedDict, data: bytes, stream_id: int):
        info(("nacm_api_post: " + headers[":path"]))

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")
        if username not in NACM_ADMINS:
            warn(username + " not allowed to access NACM data")
            response = "Forbidden"
            http_status = "403"

            response += "\n"
            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG_HTTP["SERVER_NAME"]),
            )

            prot.conn.send_headers(stream_id, response_headers)
            prot.conn.send_data(stream_id, response.encode(), end_stream=True)
        else:
            api_pth = headers[":path"][len(NACM_API_ROOT_data):]
            post(prot, data, stream_id, ds.nacm.nacm_ds, api_pth)
            ds.nacm.update()

    return post_nacm_api_closure


def create_post_api(ds: BaseDatastore):
    def post_api_closure(prot: "H2Protocol", headers: OrderedDict, data: bytes, stream_id: int):
        info(("api_post: " + headers[":path"]))
        api_pth = headers[":path"][len(API_ROOT_data):]
        post(prot, data, stream_id, ds, api_pth)

    return post_api_closure


def put(prot: "H2Protocol", data: bytes, stream_id: int, ds: BaseDatastore, pth: str):
    data_str = data.decode("utf-8")
    info("prijato: " + data_str)

    url_split = pth.split("?")
    url_path = url_split[0]
    if len(url_split) > 1:
        query_string = parse_qs(url_split[1])
    else:
        query_string = {}

    info("qs = {}".format(query_string))

    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

    rpc1 = Rpc()
    rpc1.username = username
    rpc1.path = url_path

    json_data = json.loads(data_str)

    try:
        ds.lock_data(username)
        ds.put_node_rpc(rpc1, json_data)
        response = "Done\n"
        http_status = "200"
    except DataLockError as e:
        warn(e.msg)
        response = "Internal Server Error"
        http_status = "500"
    except NacmForbiddenError as e:
        warn(e.msg)
        response = "Forbidden"
        http_status = "403"
    except NonexistentSchemaNode:
        warn("NonexistentSchemaNode: " + pth)
        response = "NonexistentSchemaNode"
        http_status = "404"
    except NonexistentInstance:
        warn("NonexistentInstance: " + pth)
        response = "NonexistentInstance"
        http_status = "404"
    finally:
        ds.unlock_data()

    response += "\n"
    response = response.encode()
    response_headers = (
        (':status', http_status),
        ('content-type', 'application/yang.api+json'),
        ('content-length', len(response)),
        ('server', CONFIG_HTTP["SERVER_NAME"]),
    )

    prot.conn.send_headers(stream_id, response_headers)
    prot.conn.send_data(stream_id, response, end_stream=True)


def create_put_nacm_api(ds: BaseDatastore):
    def put_nacm_api_closure(prot: "H2Protocol", headers: OrderedDict, data: bytes, stream_id: int):
        info(("nacm_api_put: " + headers[":path"]))

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")
        if username not in NACM_ADMINS:
            warn(username + " not allowed to access NACM data")
            response = "Forbidden"
            http_status = "403"

            response += "\n"
            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG_HTTP["SERVER_NAME"]),
            )

            prot.conn.send_headers(stream_id, response_headers)
            prot.conn.send_data(stream_id, response.encode(), end_stream=True)
        else:
            api_pth = headers[":path"][len(NACM_API_ROOT_data):]
            put(prot, data, stream_id, ds.nacm.nacm_ds, api_pth)
            ds.nacm.update()

    return put_nacm_api_closure


def create_put_api(ds: BaseDatastore):
    def put_api_closure(prot: "H2Protocol", headers: OrderedDict, data: bytes, stream_id: int):
        info(("api_put: " + headers[":path"]))
        api_pth = headers[":path"][len(API_ROOT_data):]
        put(prot, data, stream_id, ds, api_pth)

    return put_api_closure


def delete(prot: "H2Protocol", stream_id: int, ds: BaseDatastore, pth: str):
        url_split = pth.split("?")
        url_path = url_split[0]
        if len(url_split) > 1:
            query_string = parse_qs(url_split[1])
        else:
            query_string = {}

        info("qs = {}".format(query_string))

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")

        rpc1 = Rpc()
        rpc1.username = username
        rpc1.path = url_path

        try:
            ds.lock_data(username)
            ds.delete_node_rpc(rpc1)
            response = "No Content"
            http_status = "204"
        except DataLockError as e:
            warn(e.msg)
            response = "Internal Server Error"
            http_status = "500"
        except NacmForbiddenError as e:
            warn(e.msg)
            response = "Forbidden"
            http_status = "403"
        except NonexistentSchemaNode:
            warn("NonexistentSchemaNode: " + pth)
            response = "NonexistentSchemaNode"
            http_status = "404"
        except NonexistentInstance:
            warn("NonexistentInstance: " + pth)
            response = "NonexistentInstance"
            http_status = "404"
        finally:
            ds.unlock_data()

        response += "\n"
        response = response.encode()
        response_headers = (
            (':status', http_status),
            ('content-type', 'application/yang.api+json'),
            ('content-length', len(response)),
            ('server', CONFIG_HTTP["SERVER_NAME"]),
        )

        prot.conn.send_headers(stream_id, response_headers)
        prot.conn.send_data(stream_id, response, end_stream=True)


def create_nacm_api_delete(ds: BaseDatastore):
    def nacm_api_delete_closure(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
        info(("nacm_api_delete: " + headers[":path"]))
        api_pth = headers[":path"][len(NACM_API_ROOT_data):]
        delete(prot, stream_id, ds.nacm.nacm_ds, api_pth)
        ds.nacm.update()

    return nacm_api_delete_closure


def create_api_delete(ds: BaseDatastore):
    def api_delete_closure(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
        info(("api_delete: " + headers[":path"]))
        api_pth = headers[":path"][len(API_ROOT_data):]
        delete(prot, stream_id, ds, api_pth)

    return api_delete_closure
