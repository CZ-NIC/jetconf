import os
import colorlog
import getopt
import logging
import sys
import signal

from colorlog import error, info
from yaml.parser import ParserError

from yangson.enumerations import ContentType, ValidationScope
from yangson.exceptions import YangsonException
from yangson.schemanode import SchemaError, SemanticError

from . import usr_state_data_handlers
from .rest_server import RestServer
from .config import CONFIG_GLOBAL, CONFIG_KNOT, load_config, print_config
from .data import JsonDatastore
from .helpers import DataHelpers, ErrorHelpers
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES, CONF_DATA_HANDLES
from .knot_api import KNOT, knot_connect, knot_disconnect
from .usr_op_handlers import OP_HANDLERS_IMPL
from .usr_conf_data_handlers import (
    KnotConfServerListener,
    KnotConfLogListener,
    KnotConfZoneListener,
    KnotConfControlListener,
    KnotConfAclListener
)


def main():
    config_file = "config.yaml"

    # Parse command line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:")
    except getopt.GetoptError:
        print("Invalid argument detected. Possible options are: -c (config file)")
        sys.exit(1)

    for opt, arg in opts:
        if opt == "-c":
            config_file = arg

    # Load configuration
    try:
        load_config(config_file)
    except FileNotFoundError:
        print("Configuration file does not exist")
        sys.exit(1)
    except ParserError as e:
        print("Configuration syntax error: " + str(e))
        sys.exit(1)

    # Set logging level
    log_level = {
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.INFO
    }.get(CONFIG_GLOBAL["LOG_LEVEL"], logging.INFO)
    logging.root.handlers.clear()

    # Daemonize
    if CONFIG_GLOBAL["LOGFILE"] not in ("-", "stdout"):
        # Setup basic logging
        logging.basicConfig(
            format="%(asctime)s %(levelname)-8s %(message)s",
            level=log_level,
            filename=CONFIG_GLOBAL["LOGFILE"]
        )

        # Go to background
        pid = os.fork()
        if pid != 0:
            sys.exit(0)
        os.setsid()
        os.umask(0)
        pid = os.fork()
        if pid != 0:
            sys.exit(0)

        # Close standard file descriptors
        os.close(sys.stdin.fileno())
        os.close(sys.stdout.fileno())
        os.close(sys.stderr.fileno())
        fd_null = os.open("/dev/null", os.O_RDWR)
        os.dup(fd_null)
        os.dup(fd_null)
    else:
        # Setup color logging
        log_formatter = colorlog.ColoredFormatter(
            "%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(message)s",
            datefmt=None,
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red',
            },
            secondary_log_colors={},
            style='%'
        )

        log_handler = colorlog.StreamHandler()
        log_handler.setFormatter(log_formatter)
        log_handler.stream = sys.stdout

        logger = colorlog.getLogger()
        logger.addHandler(log_handler)
        logger.setLevel(log_level)

    # Print configuration
    print_config()

    # Create pidfile
    fl = os.open(CONFIG_GLOBAL["PIDFILE"], os.O_WRONLY + os.O_CREAT, 0o666)
    try:
        os.lockf(fl, os.F_TLOCK, 0)
        os.write(fl, str(os.getpid()).encode())
        os.fsync(fl)
    except BlockingIOError:
        error("Jetconf daemon already running (pidfile exists). Exiting.")
        sys.exit(1)

    # Set signal handlers
    def sig_exit_handler(signum, frame):
        os.close(fl)
        os.unlink(CONFIG_GLOBAL["PIDFILE"])
        info("Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_exit_handler)
    signal.signal(signal.SIGINT, sig_exit_handler)

    # Load data model
    datamodel = DataHelpers.load_data_model(
        CONFIG_GLOBAL["YANG_LIB_DIR"],
        CONFIG_GLOBAL["YANG_LIB_DIR"] + "yang-library-data.json"
    )

    # Datastore init
    datastore = JsonDatastore(datamodel, CONFIG_GLOBAL["DATA_JSON_FILE"], "DNS data", with_nacm=False)
    try:
        datastore.load()
        datastore.load_yl_data(CONFIG_GLOBAL["YANG_LIB_DIR"] + "yang-library-data.json")
    except (FileNotFoundError, YangsonException) as e:
        error("Could not load JSON datastore " + CONFIG_GLOBAL["DATA_JSON_FILE"])
        error(ErrorHelpers.epretty(e))
        sig_exit_handler(0, None)

    try:
        datastore.get_data_root().validate(ValidationScope.all, ContentType.config)
    except (SchemaError, SemanticError) as e:
        error("Initial validation of datastore failed")
        error(ErrorHelpers.epretty(e))
        sig_exit_handler(0, None)

    # Register configuration data node listeners
    CONF_DATA_HANDLES.register(KnotConfServerListener(datastore, "/dns-server:dns-server/server-options"))
    CONF_DATA_HANDLES.register(KnotConfLogListener(datastore, "/dns-server:dns-server/knot-dns:log"))
    CONF_DATA_HANDLES.register(KnotConfZoneListener(datastore, "/dns-server:dns-server/zones/zone"))
    CONF_DATA_HANDLES.register(KnotConfControlListener(datastore, "/dns-server:dns-server/knot-dns:control-socket"))
    CONF_DATA_HANDLES.register(KnotConfAclListener(datastore, "/dns-server:dns-server/access-control-list"))

    # Register op handlers
    OP_HANDLERS.register("dns-zone-rpcs:begin-transaction", OP_HANDLERS_IMPL.zone_begin_transaction)
    OP_HANDLERS.register("dns-zone-rpcs:commit-transaction", OP_HANDLERS_IMPL.zone_commit_transaction)
    OP_HANDLERS.register("dns-zone-rpcs:abort-transaction", OP_HANDLERS_IMPL.zone_abort_transaction)
    OP_HANDLERS.register("dns-zone-rpcs:zone-set", OP_HANDLERS_IMPL.zone_set)
    OP_HANDLERS.register("dns-zone-rpcs:zone-unset", OP_HANDLERS_IMPL.zone_unset)

    # Create and register state data node listeners
    usr_state_data_handlers.create_zone_state_handlers(STATE_DATA_HANDLES, datamodel)

    # Initialize Knot control interface
    KNOT.set_socket(CONFIG_KNOT["SOCKET"])
    datastore.commit_begin_callback = knot_connect
    datastore.commit_end_callback = knot_disconnect

    # Create HTTP server
    rest_srv = RestServer()
    rest_srv.register_api_handlers(datastore)
    rest_srv.register_static_handlers()

    # Run HTTP server
    rest_srv.run()


if __name__ == "__main__":
    main()