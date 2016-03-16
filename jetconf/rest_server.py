import asyncio
import json
import mimetypes
import os
import ssl
from collections import OrderedDict
from colorlog import error, warning as warn, info, debug
from typing import List, Tuple, Dict, Any
import yaml
from .nacm import NacmConfig
from .data import JsonDatastore, Rpc, NacmForbiddenError, DataLockError
from yangson.schema import NonexistentSchemaNode
from yangson.instance import NonexistentInstance

from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, RemoteSettingsChanged

CONFIG = {
    "DOC_ROOT": "doc-root",
    "DOC_DEFAULT_NAME": "index.html",
    "RESTCONF_API_ROOT": "/restconf",
    "RESTCONF_NACM_API_ROOT": "/restconf_nacm",
    "SERVER_NAME": "hyper-h2",
    "PORT": 8443,

    "SERVER_SSL_CERT": "server.crt",
    "SERVER_SSL_PRIVKEY": "server.key",
    "CA_CERT": "ca.pem"
}

# NACM_ADMINS = []


class CertHelpers:
    @staticmethod
    def get_field(cert: Dict[str, Any], key: str) -> str:
            return ([x[0][1] for x in cert["subject"] if x[0][0] == key] or [None])[0]


class H2Protocol(asyncio.Protocol):
    def __init__(self):
        self.conn = H2Connection(client_side=False)
        self.transport = None
        self.reqs_waiting_upload = dict()
        self.client_cert = None     # type: Dict[str, Any]

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.conn.initiate_connection()
        self.transport.write(self.conn.data_to_send())
        self.client_cert = self.transport.get_extra_info('peercert')

    def data_received(self, data: bytes):
        events = self.conn.receive_data(data)
        self.transport.write(self.conn.data_to_send())
        for event in events:
            if isinstance(event, RequestReceived):
                # Handle request
                headers = OrderedDict(event.headers)

                http_method = headers[":method"]
                if http_method == "GET":
                    # Handle GET
                    self.handle_get(headers, event.stream_id)
                elif http_method in ("PUT", "POST"):
                    # Store headers and wait for data upload
                    self.reqs_waiting_upload[event.stream_id] = headers
                else:
                    warn("Unknown http method \"{}\"".format(headers[":method"]))
            elif isinstance(event, DataReceived):
                self.http_handle_upload(event.data, event.stream_id)
            elif isinstance(event, RemoteSettingsChanged):
                self.conn.acknowledge_settings(event)

            self.transport.write(self.conn.data_to_send())

    def http_handle_upload(self, data: bytes, stream_id: int):
        try:
            req_headers = self.reqs_waiting_upload.pop(stream_id)
        except KeyError:
            return

        {"PUT": self.handle_put, "POST": self.handle_post}[req_headers[":method"]](req_headers, data, stream_id)

    def handle_get(self, headers: OrderedDict, stream_id: int):
        response = None

        if headers[":path"] == CONFIG["RESTCONF_NACM_API_ROOT"]:
            # Top level api resource (appendix D.1.1)
            response = ("{\n"
                        "    \"ietf-restconf:restconf\": {\n"
                        "        \"data\" : [ null ],\n"
                        "        \"operations\" : [ null ]\n"
                        "    }\n"
                        "}")
            response_headers = (
                (':status', '200'),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )
            self.conn.send_headers(stream_id, response_headers)
            self.conn.send_data(stream_id, response.encode(), end_stream=True)

        elif headers[":path"] == CONFIG["RESTCONF_API_ROOT"]:
            # Top level api resource (appendix D.1.1)
            response = ("{\n"
                        "    \"ietf-restconf:restconf\": {\n"
                        "        \"data\" : [ null ],\n"
                        "        \"operations\" : [ null ]\n"
                        "    }\n"
                        "}")
            response_headers = (
                (':status', '200'),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )
            self.conn.send_headers(stream_id, response_headers)
            self.conn.send_data(stream_id, response.encode(), end_stream=True)

        elif headers[":path"].startswith(os.path.join(CONFIG["RESTCONF_NACM_API_ROOT"], "data")):
            # NACM api request
            info(("nacm_api_get: " + headers[":path"]))

            username = CertHelpers.get_field(self.client_cert, "emailAddress")
            if username not in NACM_ADMINS:
                warn(username + " not allowed to access NACM data")
                response = "Forbidden"
                http_status = "403"
            else:
                pth = headers[":path"][len(os.path.join(CONFIG["RESTCONF_NACM_API_ROOT"], "data")):]

                rpc1 = Rpc()
                rpc1.username = username
                rpc1.path = pth

                try:
                    ex_datastore.nacm.nacm_ds.lock_data(username)
                    n = ex_datastore.nacm.nacm_ds.get_node_rpc(rpc1)
                    response = json.dumps(n.value, indent=4)
                    http_status = "200"
                except DataLockError as e:
                    warn(e.msg)
                    response = "Internal Server Error"
                    http_status = "500"
                except NonexistentSchemaNode:
                    warn("NonexistentSchemaNode: " + pth)
                    response = "NonexistentSchemaNode"
                    http_status = "404"
                except NonexistentInstance:
                    warn("NonexistentInstance: " + pth)
                    response = "NonexistentInstance"
                    http_status = "404"
                finally:
                    ex_datastore.nacm.nacm_ds.unlock_data()

            response += "\n"
            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )

            self.conn.send_headers(stream_id, response_headers)
            self.conn.send_data(stream_id, response.encode(), end_stream=True)

        elif headers[":path"].startswith(os.path.join(CONFIG["RESTCONF_API_ROOT"], "data")):
            # api request
            info(("api_get: " + headers[":path"]))

            username = CertHelpers.get_field(self.client_cert, "emailAddress")

            pth = headers[":path"][len(os.path.join(CONFIG["RESTCONF_API_ROOT"], "data")):]

            rpc1 = Rpc()
            rpc1.username = username
            rpc1.path = pth

            try:
                ex_datastore.lock_data(username)
                n = ex_datastore.get_node_rpc(rpc1)
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
                ex_datastore.unlock_data()

            response += "\n"
            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )

            self.conn.send_headers(stream_id, response_headers)
            self.conn.send_data(stream_id, response.encode(), end_stream=True)

        else:
            # Ordinary file on filesystem
            file_path = os.path.join(CONFIG["DOC_ROOT"], headers[":path"][1:].replace("..", "").replace("&", ""))

            if os.path.isdir(file_path):
                file_path = os.path.join(file_path, CONFIG["DOC_DEFAULT_NAME"])

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
                    ('server', CONFIG["SERVER_NAME"]),
                )
                self.conn.send_headers(stream_id, response_headers, end_stream=True)
                return

            info("Serving ordinary file {} of type \"{}\"".format(file_path, ctype))
            response_headers = (
                (':status', '200'),
                ('content-type', ctype),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )
            self.conn.send_headers(stream_id, response_headers)

            def split_arr(arr, chunk_size):
                for i in range(0, len(arr), chunk_size):
                    yield arr[i:i + chunk_size]

            for data_chunk in split_arr(response, self.conn.max_outbound_frame_size):
                self.conn.send_data(stream_id, data_chunk, end_stream=False)

            self.conn.send_data(stream_id, bytes(), end_stream=True)

    def handle_put(self, headers: OrderedDict, data: bytes, stream_id: int):
        print("put")

    def handle_post(self, headers: OrderedDict, data: bytes, stream_id: int):
        data_str = data.decode("utf-8")
        info("prijato: " + data_str)

        if headers[":path"].startswith(os.path.join(CONFIG["RESTCONF_NACM_API_ROOT"], "data")):
            info(("nacm_api_post: " + headers[":path"]))

            username = CertHelpers.get_field(self.client_cert, "emailAddress")

            pth = headers[":path"][len(os.path.join(CONFIG["RESTCONF_NACM_API_ROOT"], "data")):]

            rpc1 = Rpc()
            rpc1.username = username
            rpc1.path = pth

            try:
                ex_datastore.nacm.nacm_ds.lock_data(username)
                ex_datastore.nacm.nacm_ds.put_node_rpc(rpc1, json.loads(data_str))
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
                ex_datastore.nacm.nacm_ds.unlock_data()
                ex_datastore.nacm.update(ex_datastore.nacm.nacm_ds.get_data_root().member("ietf-netconf-acm:nacm"))

            response += "\n"
            response = response.encode()
            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )

            self.conn.send_headers(stream_id, response_headers)
            self.conn.send_data(stream_id, response, end_stream=True)

        else:
            # Unknown POST URL
            pass


def run():
    global ex_datastore
    global NACM_ADMINS

    try:
        with open("jetconf/config.yaml") as conf_fd:
            conf_yaml = yaml.load(conf_fd)
            try:
                CONFIG.update(conf_yaml["HTTP_SERVER"])
            except KeyError:
                pass
            try:
                NACM_ADMINS = conf_yaml["NACM"]["ALLOWED_USERS"]
            except KeyError:
                pass
    except FileNotFoundError:
        warn("Configuration file does not exist")

    info("Using config:\n" + yaml.dump([CONFIG, ], default_flow_style=False))

    nacm_data = JsonDatastore("./data", "./data/yang-library-data.json", "NACM data")
    nacm_data.load("jetconf/example-data-nacm.json")

    nacmc = NacmConfig(nacm_data)

    ex_datastore = JsonDatastore("./data", "./data/yang-library-data.json", "DNS data")
    ex_datastore.load("jetconf/example-data.json")
    ex_datastore.register_nacm(nacmc)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION)
    ssl_context.load_cert_chain(certfile=CONFIG["SERVER_SSL_CERT"], keyfile=CONFIG["SERVER_SSL_PRIVKEY"])
    try:
        ssl_context.set_alpn_protocols(["h2"])
    except AttributeError:
        info("Python not compiled with ALPN support, using NPN instead.")
        ssl_context.set_npn_protocols(["h2"])
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.load_verify_locations(cafile=CONFIG["CA_CERT"])

    loop = asyncio.get_event_loop()

    # Each client connection will create a new protocol instance
    listener = loop.create_server(H2Protocol, "127.0.0.1", CONFIG["PORT"], ssl=ssl_context)
    server = loop.run_until_complete(listener)

    info("Server started on {}".format(server.sockets[0].getsockname()))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
