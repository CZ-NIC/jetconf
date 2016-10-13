import asyncio
import ssl
from io import BytesIO
from collections import OrderedDict
from colorlog import error, warning as warn, info, debug
from typing import List, Tuple, Dict, Any, Callable

from h2.connection import H2Connection
from h2.errors import PROTOCOL_ERROR, ENHANCE_YOUR_CALM
from h2.events import DataReceived, RequestReceived, RemoteSettingsChanged, StreamEnded

import jetconf.http_handlers as handlers
from .config import CONFIG_HTTP, API_ROOT_data, API_ROOT_STAGING_data, API_ROOT_ops
from .data import BaseDatastore


# Function(method, path) -> bool
HandlerConditionT = Callable[[str, str], bool]

h2_handlers = None  # type: HandlerList


class RequestData:
    def __init__(self, headers: OrderedDict, data: BytesIO):
        self.headers = headers
        self.data = data
        self.data_overflow = False


class HandlerList:
    def __init__(self):
        self.handlers = []              # type: List[Tuple[HandlerConditionT, Callable]]
        self.default_handler = None     # type: Callable

    def register_handler(self, condition: HandlerConditionT, handler: Callable):
        self.handlers.append((condition, handler))

    def register_default_handler(self, handler: Callable):
        self.default_handler = handler

    def get_handler(self, method: str, path: str) -> Callable:
        for h in self.handlers:
            if h[0](method, path):
                return h[1]

        return self.default_handler


class H2Protocol(asyncio.Protocol):
    def __init__(self):
        self.conn = H2Connection(client_side=False)
        self.transport = None
        self.stream_data = {}       # type: Dict[int, RequestData]
        self.client_cert = None     # type: Dict[str, Any]

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        self.conn.initiate_connection()
        self.transport.write(self.conn.data_to_send())
        self.client_cert = self.transport.get_extra_info('peercert')

    def send_empty(self, stream_id: int, status_code: str, status_msg: str, status_in_body: bool = True):
        response = status_code + " " + status_msg + "\n" if status_in_body else ""
        response_bytes = response.encode()
        response_headers = (
            (":status", status_code),
            ("content-type", "text/plain"),
            ("content-length", len(response_bytes)),
            ("server", CONFIG_HTTP["SERVER_NAME"]),
        )

        self.conn.send_headers(stream_id, response_headers)
        self.conn.send_data(stream_id, response_bytes, end_stream=True)

    def data_received(self, data: bytes):
        events = self.conn.receive_data(data)
        for event in events:
            if isinstance(event, RequestReceived):
                # Store request headers
                headers = OrderedDict(event.headers)
                request_data = RequestData(headers, BytesIO())
                self.stream_data[event.stream_id] = request_data
            elif isinstance(event, DataReceived):
                # Store incoming data
                try:
                    stream_data = self.stream_data[event.stream_id]
                except KeyError:
                    self.conn.reset_stream(event.stream_id, error_code=PROTOCOL_ERROR)
                else:
                    # Check if incoming data are not excessively large
                    if (stream_data.data.tell() + len(event.data)) < (CONFIG_HTTP["UPLOAD_SIZE_LIMIT"] * 1048576):
                        stream_data.data.write(event.data)
                    else:
                        stream_data.data_overflow = True
                        self.conn.reset_stream(event.stream_id, error_code=ENHANCE_YOUR_CALM)
            elif isinstance(event, StreamEnded):
                # Process request
                try:
                    request_data = self.stream_data.pop(event.stream_id)
                except KeyError:
                    self.send_empty(event.stream_id, "400", "Bad Request")
                else:
                    if request_data.data_overflow:
                        self.send_empty(event.stream_id, "406", "Not Acceptable")
                    else:
                        headers = request_data.headers
                        body = request_data.data.getvalue().decode('utf-8')

                        http_method = headers[":method"]
                        if http_method in ("GET", "DELETE"):
                            self.handle_get_delete(headers, event.stream_id)
                        elif http_method in ("PUT", "POST"):
                            self.handle_put_post(headers, event.stream_id, body)
                        else:
                            warn("Unknown http method \"{}\"".format(headers[":method"]))
                            self.send_empty(event.stream_id, "405", "Method Not Allowed")
            # elif isinstance(event, RemoteSettingsChanged):
            #     changed_settings = {}
            #     for s in event.changed_settings.items():
            #         changed_settings[s[0]] = s[1].new_value
            #     self.conn.update_settings(changed_settings)
            # else:
            #     print(type(event))

            dts = self.conn.data_to_send()
            if dts:
                self.transport.write(dts)

    def handle_put_post(self, headers: OrderedDict, stream_id: int, data: bytes):
        # Handle PUT, POST
        url_path = headers[":path"].split("?")[0]

        h = h2_handlers.get_handler(headers[":method"], url_path)
        if h:
            h(self, stream_id, headers, data)
        else:
            self.send_empty(stream_id, "400", "Bad Request")

    def handle_get_delete(self, headers: OrderedDict, stream_id: int):
        # Handle GET, DELETE
        url_path = headers[":path"].split("?")[0]

        h = h2_handlers.get_handler(headers[":method"], url_path)
        if h:
            h(self, stream_id, headers)
        else:
            self.send_empty(stream_id, "400", "Bad Request")


class RestServer:
    def __init__(self):
        # HTTP server init
        self.http_handlers = HandlerList()
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION)
        ssl_context.load_cert_chain(certfile=CONFIG_HTTP["SERVER_SSL_CERT"], keyfile=CONFIG_HTTP["SERVER_SSL_PRIVKEY"])
        try:
            ssl_context.set_alpn_protocols(["h2"])
        except AttributeError:
            info("Python not compiled with ALPN support, using NPN instead.")
            ssl_context.set_npn_protocols(["h2"])
        if not CONFIG_HTTP["DBG_DISABLE_CERTS"]:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_verify_locations(cafile=CONFIG_HTTP["CA_CERT"])

        self.loop = asyncio.get_event_loop()

        # Each client connection will create a new H2Protocol instance
        listener = self.loop.create_server(H2Protocol, "127.0.0.1", CONFIG_HTTP["PORT"], ssl=ssl_context)
        self.server = self.loop.run_until_complete(listener)

    def register_api_handlers(self, datastore: BaseDatastore):
        global h2_handlers

        # Register HTTP handlers
        api_get_root = handlers.api_root_handler
        api_get = handlers.create_get_api(datastore)
        api_get_staging = handlers.create_get_staging_api(datastore)
        api_post = handlers.create_post_api(datastore)
        api_put = handlers.create_put_api(datastore)
        api_delete = handlers.create_api_delete(datastore)
        api_op = handlers.create_api_op(datastore)

        self.http_handlers.register_handler(lambda m, p: (m == "GET") and (p == CONFIG_HTTP["API_ROOT"]), api_get_root)
        self.http_handlers.register_handler(lambda m, p: (m == "GET") and (p.startswith(API_ROOT_data)), api_get)
        self.http_handlers.register_handler(lambda m, p: (m == "GET") and (p.startswith(API_ROOT_STAGING_data)), api_get_staging)
        self.http_handlers.register_handler(lambda m, p: (m == "POST") and (p.startswith(API_ROOT_data)), api_post)
        self.http_handlers.register_handler(lambda m, p: (m == "PUT") and (p.startswith(API_ROOT_data)), api_put)
        self.http_handlers.register_handler(lambda m, p: (m == "DELETE") and (p.startswith(API_ROOT_data)), api_delete)
        self.http_handlers.register_handler(lambda m, p: (m == "POST") and (p.startswith(API_ROOT_ops)), api_op)

        h2_handlers = self.http_handlers

    def register_static_handlers(self):
        global h2_handlers

        self.http_handlers.register_handler(lambda m, p: m == "GET", handlers.get_file)
        self.http_handlers.register_default_handler(handlers.unknown_req_handler)

        h2_handlers = self.http_handlers

    def run(self):
        info("Server started on {}".format(self.server.sockets[0].getsockname()))
        self.loop.run_forever()

    def shutdown(self):
        self.server.close()
        self.loop.run_until_complete(self.server.wait_closed())
        self.loop.close()
