import json
import os
import mimetypes
from collections import OrderedDict
from colorlog import error, warning as warn, info, debug
from urllib.parse import parse_qs

from yangson.schema import NonexistentSchemaNode
from yangson.instance import NonexistentInstance

from .config import CONFIG_HTTP, NACM_ADMINS, API_ROOT_data, NACM_API_ROOT_data
from .helpers import CertHelpers
from .data import BaseDatastore, Rpc, DataLockError, NacmForbiddenError, InstanceAlreadyPresent


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


def get(prot: "H2Protocol", headers: OrderedDict, stream_id: int, ds, pth):
    username = CertHelpers.get_field(prot.client_cert, "emailAddress")

    rpc1 = Rpc()
    rpc1.username = username
    rpc1.path = pth

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

        url_split = headers[":path"].split("?")
        url_path = url_split[0]
        if len(url_split) > 1:
            query_string = parse_qs(url_split[1])
        else:
            query_string = {}

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
            pth = url_path[len(NACM_API_ROOT_data):] or "/"
            get(prot, headers, stream_id, ds.nacm.nacm_ds, pth)

    return get_nacm_api_closure


def create_get_api(ds: BaseDatastore):
    def get_api_closure(prot: "H2Protocol", headers: OrderedDict, stream_id: int):
        # api request
        info(("api_get: " + headers[":path"]))

        url_split = headers[":path"].split("?")
        url_path = url_split[0]
        if len(url_split) > 1:
            query_string = parse_qs(url_split[1])
        else:
            query_string = {}

        pth = url_path[len(API_ROOT_data):] or "/"

        get(prot, headers, stream_id, ds, pth)

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
    subtype = ctype.split('/', 1)[1]

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


def create_put_post_nacm_api(ds: BaseDatastore):
    def put_post_nacm_api_closure(prot: "H2Protocol", headers: OrderedDict, data: bytes, stream_id: int):
        data_str = data.decode("utf-8")
        info("prijato: " + data_str)

        url_split = headers[":path"].split("?")
        path = url_split[0]
        if len(url_split) > 1:
            query_string = parse_qs(url_split[1])
        else:
            query_string = {}

        info(("nacm_api_put: " + path))
        info("qs = {}".format(query_string))

        username = CertHelpers.get_field(prot.client_cert, "emailAddress")

        pth = path[len(NACM_API_ROOT_data):]

        rpc1 = Rpc()
        rpc1.username = username
        rpc1.path = pth

        json_data = json.loads(data_str)

        try:
            ds.nacm.nacm_ds.lock_data(username)
            if headers[":method"] == "PUT":
                ds.nacm.nacm_ds.put_node_rpc(rpc1, json_data)
            else:
                ins_pos = (query_string.get("insert") or [None])[0]
                ds.nacm.nacm_ds.create_node_rpc(rpc1, json_data, insert=ins_pos)
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
            ds.nacm.nacm_ds.unlock_data()
            ds.nacm.update(ds.nacm.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm"))

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

    return put_post_nacm_api_closure
