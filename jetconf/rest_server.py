import asyncio
import json
import mimetypes
import os
import ssl
from collections import OrderedDict
import sys
import logging
import colorlog
from colorlog import error, warning as warn, info, debug
from typing import List, Tuple, Dict, Any
import yaml
import copy
import nacm
import yang_json_path

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


class CertHelpers:
    @staticmethod
    def get_field(cert: Dict[str, Any], key: str) -> str:
            return ([x[0][1] for x in cert["subject"] if x[0][0] == key] or [None])[0]


class H2Protocol(asyncio.Protocol):
    def __init__(self):
        self.conn = H2Connection(client_side=False)
        self.transport = None
        self.reqs_waiting_upload = dict()
        self.client_cert = None

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.conn.initiate_connection()
        self.transport.write(self.conn.data_to_send())
        self.client_cert = self.transport.get_extra_info('peercert')
        # print("cert = {}".format(self.client_cert))

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
        parsed_url = yang_json_path.URLPath(headers[":path"])
        if parsed_url.path_equals(CONFIG["RESTCONF_NACM_API_ROOT"]):
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

        elif parsed_url.path_contains(os.path.join(CONFIG["RESTCONF_NACM_API_ROOT"], "data")):
            # NACM api request
            info(("nacm_api_get: " + headers[":path"]))

            username = CertHelpers.get_field(self.client_cert, "emailAddress")

            parsed_url.path_segments = parsed_url.path_segments[2:]  # TODO: Hack
            print(parsed_url.path_segments)

            nacm_config.lock_data(username)
            _node = copy.deepcopy(nacm_config.json.select_data_node(parsed_url))
            nacm_config.unlock_data()

            if not _node:
                warn("Node not found")
                response = "Not found"
                http_status = "404"
            else:
                _doc = nacm.JsonDoc(_node[-1], parsed_url)
                _rpc = nacm.NacmRpc(nacm_config, None, username)
                _rpc.check_data_read(_node[-1], _doc)
                response = json.dumps(_doc.root)
                http_status = "200"

            response_headers = (
                (':status', http_status),
                ('content-type', 'application/yang.api+json'),
                ('content-length', len(response)),
                ('server', CONFIG["SERVER_NAME"]),
            )
            self.conn.send_headers(stream_id, response_headers)
            self.conn.send_data(stream_id, response.encode(), end_stream=True)

        elif parsed_url.path_contains(CONFIG["RESTCONF_API_ROOT"]):
            # api request
            pass

        else:
            # Ordinary file on filesystem
            file_path = CONFIG["DOC_ROOT"] + "/" + parsed_url.path_str.replace("..", "").replace("&", "")

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
        print("post")
        parsed_url = yang_json_path.URLPath(headers[":path"])
        print(json.dumps({"query": parsed_url.query_table, "path": parsed_url.path_list}, indent=4))

        print("prijato: " + data.decode("utf-8"))
        print(json.dumps({"headers": headers}, indent=4))

        response = "Jmenujes se {} a tvuj e-mail je {}\n".format(
                CertHelpers.get_field(self.client_cert, "organizationName"),
                CertHelpers.get_field(self.client_cert, "emailAddress")
        ).encode()

        response_headers = (
            (':status', '200'),
            ('content-type', 'application/yang.api+json'),
            ('content-length', len(response)),
            ('server', CONFIG["SERVER_NAME"]),
        )

        self.conn.send_headers(stream_id, response_headers)
        self.conn.send_data(stream_id, response, end_stream=True)


if __name__ == "__main__":
    colorlog.basicConfig(format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(message)s", level=logging.INFO,
                         stream=sys.stdout)

    try:
        with open("config.yaml") as conf_fd:
            conf_yaml = yaml.load(conf_fd)
            CONFIG.update(conf_yaml.get("HTTP_SERVER", {}))
    except FileNotFoundError:
        warn("Configuration file does not exist")

    info("Using config:\n" + yaml.dump([CONFIG, ], default_flow_style=False))

    global nacm_config
    nacm_config = nacm.NacmConfig()
    nacm_config.load_json("example-data.json")

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
