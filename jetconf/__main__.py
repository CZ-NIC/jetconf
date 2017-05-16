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

from . import usr_state_data_handlers, usr_conf_data_handlers, usr_op_handlers
from .usr_datastore import UserDatastore
from .rest_server import RestServer
from .config import CONFIG_GLOBAL, CONFIG_NACM, load_config, print_config
from .helpers import DataHelpers, ErrorHelpers


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
    yang_lib_file = os.path.join(CONFIG_GLOBAL["YANG_LIB_DIR"], "yang-library-data.json")
    datamodel = DataHelpers.load_data_model(
        CONFIG_GLOBAL["YANG_LIB_DIR"],
        yang_lib_file
    )

    # Datastore init
    datastore = UserDatastore(datamodel, CONFIG_GLOBAL["DATA_JSON_FILE"], with_nacm=CONFIG_NACM["ENABLED"])
    try:
        datastore.load()
        datastore.load_yl_data(yang_lib_file)
    except (FileNotFoundError, YangsonException) as e:
        error("Could not load JSON datastore " + CONFIG_GLOBAL["DATA_JSON_FILE"])
        error(ErrorHelpers.epretty(e))
        sig_exit_handler(0, None)

    # Validate datastore on startup
    try:
        datastore.get_data_root().validate(ValidationScope.all, ContentType.config)
    except (SchemaError, SemanticError) as e:
        error("Initial validation of datastore failed")
        error(ErrorHelpers.epretty(e))
        sig_exit_handler(0, None)

    # Register handlers for configuration data
    usr_conf_data_handlers.register_conf_handlers(datastore)

    # Register handlers for state data
    usr_state_data_handlers.register_state_handlers(datastore)

    # Register handlers for operations
    usr_op_handlers.register_op_handlers()

    # Create HTTP server
    rest_srv = RestServer()
    rest_srv.register_api_handlers(datastore)
    rest_srv.register_static_handlers()

    # Run HTTP server
    rest_srv.run()


if __name__ == "__main__":
    main()
