import os

import colorlog
import getopt
import logging
import sys
import signal

from importlib import import_module
from yangson.enumerations import ContentType
from . import usr_op_handlers, usr_state_data_handlers
from .rest_server import RestServer
from .config import CONFIG, load_config, print_config
from .nacm import NacmConfig
from .data import JsonDatastore
from .helpers import DataHelpers
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES, CONF_DATA_HANDLES
from .knot_api import knot_api_init, knot_connect, knot_disconnect
from .usr_conf_data_handlers import *


def main():
    # Load configuration
    load_config("jetconf/config.yaml")

    log_level = {
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.INFO
    }.get(CONFIG["GLOBAL"]["LOG_LEVEL"], logging.INFO)
    logging.root.handlers.clear()

    # Daemonize
    if CONFIG["GLOBAL"]["LOGFILE"] not in ("-", "stdout"):
        # Setup basic logging
        logging.basicConfig(
            format="%(asctime)s %(levelname)-8s %(message)s",
            level=log_level,
            filename=CONFIG["GLOBAL"]["LOGFILE"]
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
    fl = os.open(CONFIG["GLOBAL"]["PIDFILE"], os.O_WRONLY + os.O_CREAT, 0o666)
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
        os.unlink(CONFIG["GLOBAL"]["PIDFILE"])
        info("Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_exit_handler)
    signal.signal(signal.SIGINT, sig_exit_handler)

    # Load data model
    datamodel = DataHelpers.load_data_model("data/", "data/yang-library-data.json")

    # Datastore init
    datastore = JsonDatastore(datamodel, "jetconf/example-data.json", "DNS data", with_nacm=True)
    datastore.load()
    datastore.load_yl_data("data/yang-library-data.json")

    datastore.get_data_root().validate(ContentType.config)

    # Register schema listeners
    CONF_DATA_HANDLES.register_handler(KnotConfServerListener(datastore, "/dns-server:dns-server/server-options"))
    CONF_DATA_HANDLES.register_handler(KnotConfLogListener(datastore, "/dns-server:dns-server/knot-dns:log"))
    CONF_DATA_HANDLES.register_handler(KnotConfZoneListener(datastore, "/dns-server:dns-server/zones"))
    CONF_DATA_HANDLES.register_handler(KnotConfControlListener(datastore, "/dns-server:dns-server/knot-dns:control-socket"))
    CONF_DATA_HANDLES.register_handler(KnotConfAclListener(datastore, "/dns-server:dns-server/access-control-list"))
    CONF_DATA_HANDLES.register_handler(KnotZoneDataListener(datastore, "/dns-zones:zone-data"))

    # Register op handlers
    OP_HANDLERS.register_handler("generate-key", usr_op_handlers.sign_op_handler)

    # Create and register state data handlers
    usr_state_data_handlers.create_zone_state_handlers(STATE_DATA_HANDLES, datamodel)

    # Initialize Knot control interface
    knot_api_init()
    datastore.commit_begin_callback = knot_connect
    datastore.commit_end_callback = knot_disconnect

    # Create HTTP server
    rest_srv = RestServer()
    rest_srv.register_api_handlers(datastore)
    rest_srv.register_static_handlers()

    # Run HTTP server
    rest_srv.run()


if __name__ == "__main__":
    opts, args = (None, None)
    test_module = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:")
    except getopt.GetoptError:
        print("Invalid argument detected. Possibles are: -t (test module)")
        exit()

    for opt, arg in opts:
        if opt == '-t':
            test_module = arg

    if test_module is not None:
        try:
            tm = import_module("." + test_module, "jetconf")
            tm.test()
        except ImportError as e:
            print(e.msg)

    else:
        main()
