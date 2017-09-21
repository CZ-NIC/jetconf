import os
import signal

from importlib import import_module
from pkg_resources import resource_string

from yangson.enumerations import ContentType, ValidationScope
from yangson.exceptions import YangsonException
from yangson.schemanode import SchemaError, SemanticError
from yangson.datamodel import DataModel

from . import op_internal
from .rest_server import RestServer
from .helpers import ErrorHelpers
from .config import JcConfig
from .errors import JetconfInitError

JC = None


class Jetconf:
    def __init__(self, config: JcConfig):
        self.config = config
        self.datastore = None
        self.fl = -1
        self.backend_initiated = False
        self.rest_srv = None
        self.usr_init = None

    def init(self):
        # Create pidfile
        self.fl = os.open(self.config.glob["PIDFILE"], os.O_WRONLY + os.O_CREAT, 0o666)
        try:
            os.lockf(self.fl, os.F_TLOCK, 0)
            os.write(self.fl, str(os.getpid()).encode())
            os.fsync(self.fl)
        except BlockingIOError:
            os.close(self.fl)
            self.fl = -1
            raise JetconfInitError("Jetconf already running (pidfile exists)")

        # Set signal handlers
        # def sig_exit_handler(signum, frame):
        #     self.exit_clean(0)
        #
        # signal.signal(signal.SIGTERM, sig_exit_handler)
        # signal.signal(signal.SIGINT, sig_exit_handler)

        # Import backend modules
        backend_package = self.config.glob["BACKEND_PACKAGE"]
        try:
            usr_state_data_handlers = import_module(backend_package + ".usr_state_data_handlers")
            usr_conf_data_handlers = import_module(backend_package + ".usr_conf_data_handlers")
            usr_op_handlers = import_module(backend_package + ".usr_op_handlers")
            usr_datastore = import_module(backend_package + ".usr_datastore")
        except ImportError as e:
            raise JetconfInitError(
                "Cannot import backend package \"{}\", reason: {}".format(backend_package, ErrorHelpers.epretty(e))
            )

        try:
            self.usr_init = import_module(backend_package + ".usr_init")
        except ImportError:
            pass

        # Load data model
        yang_mod_dir = self.config.glob["YANG_LIB_DIR"]
        yang_lib_str = resource_string(backend_package, "yang-library-data.json").decode("utf-8")
        datamodel = DataModel(yang_lib_str, [yang_mod_dir])

        # Datastore init
        datastore = usr_datastore.UserDatastore(
            datamodel,
            self.config.glob["DATA_JSON_FILE"],
            with_nacm=self.config.nacm["ENABLED"]
        )
        self.datastore = datastore
        try:
            datastore.load()
        except (FileNotFoundError, YangsonException) as e:
            raise JetconfInitError(
                "Cannot load JSON data file \"{}\", reason: {}".format(
                    self.config.glob["DATA_JSON_FILE"], ErrorHelpers.epretty(e)
                )
            )

        # Validate datastore on startup
        try:
            datastore.get_data_root().validate(ValidationScope.all, ContentType.config)
        except (SchemaError, SemanticError) as e:
            raise JetconfInitError("Initial validation of datastore failed, reason: {}".format(ErrorHelpers.epretty(e)))

        # Register handlers for configuration data
        usr_conf_data_handlers.register_conf_handlers(datastore)

        # Register handlers for state data
        usr_state_data_handlers.register_state_handlers(datastore)

        # Register handlers for operations
        op_internal.register_op_handlers(datastore)
        usr_op_handlers.register_op_handlers(datastore)

        # Init backend package
        if self.usr_init is not None:
            try:
                self.usr_init.jc_startup()
                self.backend_initiated = True
            except Exception as e:
                raise JetconfInitError("Backend initialization failed, reason: {}".format(ErrorHelpers.epretty(e)))

        # Create HTTP server
        self.rest_srv = RestServer()
        self.rest_srv.register_api_handlers(datastore)
        self.rest_srv.register_static_handlers()

    def run(self):
        # Set signal handlers
        def sig_exit_handler():
            self.stop()

        self.rest_srv.loop.add_signal_handler(signal.SIGTERM, sig_exit_handler)
        self.rest_srv.loop.add_signal_handler(signal.SIGINT, sig_exit_handler)

        # Run HTTP server (this will block until shutdown)
        self.rest_srv.run()

    def stop(self):
        # Stop event loop
        if (self.rest_srv is not None) and (self.rest_srv.loop.is_running()):
            self.rest_srv.loop.stop()

    def cleanup(self):
        # Shutdown server
        if self.rest_srv is not None:
            self.rest_srv.shutdown()
            self.rest_srv = None

        # Close lockfile
        if self.fl > 0:
            os.close(self.fl)
            os.unlink(self.config.glob["PIDFILE"])
            self.fl = -1

        # De-init backend
        if (self.usr_init is not None) and self.backend_initiated:
            self.usr_init.jc_end()
            self.backend_initiated = False
