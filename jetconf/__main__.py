import os
import colorlog
import getopt
import logging
import sys
import signal

from importlib import import_module
from pkg_resources import resource_string, get_distribution
from colorlog import error, info
from yaml.parser import ParserError

from yangson.enumerations import ContentType, ValidationScope
from yangson.exceptions import YangsonException
from yangson.schemanode import SchemaError, SemanticError
from yangson.datamodel import DataModel

from . import op_internal
from .rest_server import RestServer
from .config import CONFIG_GLOBAL, CONFIG_NACM, load_config, validate_config, print_config
from .helpers import ErrorHelpers


def print_help():
    print("Jetconf command line options:")
    print("-c [config file]        | Pass the configuration file in YAML format")
    print("-v                      | Print version info")
    print("-h                      | Display this help")


def main():
    config_file = "config.yaml"

    # Check for Python version
    if sys.version_info < (3, 5):
        print("Jetconf requires Python version 3.5 or higher")
        sys.exit(1)

    # Get Jetconf version
    jetconf_version = get_distribution("jetconf").version

    # Parse command line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:vh")
    except getopt.GetoptError:
        print("Error: invalid argument detected.")
        print_help()
        sys.exit(1)

    for opt, arg in opts:
        if opt == "-c":
            config_file = arg
        elif opt == "-v":
            print("Jetconf version {}".format(jetconf_version))
            sys.exit(0)
        elif opt == "-h":
            print_help()
            sys.exit(0)

    # Load configuration
    try:
        load_config(config_file)
    except FileNotFoundError:
        print("Configuration file does not exist")
        sys.exit(1)
    except ParserError as e:
        print("Configuration syntax error: " + str(e))
        sys.exit(1)

    # Validate configuration
    try:
        validate_config()
    except ValueError as e:
        print("Error: " + str(e))
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

    # Print version
    info("Jetconf version {}".format(jetconf_version))

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

    # Import backend modules
    backend_package = CONFIG_GLOBAL["BACKEND_PACKAGE"]
    try:
        usr_state_data_handlers = import_module(backend_package + ".usr_state_data_handlers")
        usr_conf_data_handlers = import_module(backend_package + ".usr_conf_data_handlers")
        usr_op_handlers = import_module(backend_package + ".usr_op_handlers")
        usr_datastore = import_module(backend_package + ".usr_datastore")
    except ImportError as e:
        error(ErrorHelpers.epretty(e))
        error("Cannot import backend package \"{}\". Exiting.".format(backend_package))
        sys.exit(1)

    # Load data model
    yang_mod_dir = CONFIG_GLOBAL["YANG_LIB_DIR"]
    yang_lib_str = resource_string(backend_package, "yang-library-data.json").decode("utf-8")
    datamodel = DataModel(yang_lib_str, [yang_mod_dir])

    # Datastore init
    datastore = usr_datastore.UserDatastore(datamodel, CONFIG_GLOBAL["DATA_JSON_FILE"], with_nacm=CONFIG_NACM["ENABLED"])
    try:
        datastore.load()
    except (FileNotFoundError, YangsonException) as e:
        error("Cannot load JSON datastore " + CONFIG_GLOBAL["DATA_JSON_FILE"])
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
    op_internal.register_op_handlers(datastore)
    usr_op_handlers.register_op_handlers(datastore)

    # Write datastore content to the backend application (if required)
    try:
        confh_ros = usr_conf_data_handlers.run_on_startup
    except AttributeError:
        pass
    else:
        try:
            confh_ros()
        except Exception as e:
            error("Writing configuration to backend failed")
            error(ErrorHelpers.epretty(e))
            sig_exit_handler(0, None)

    # Create HTTP server
    rest_srv = RestServer()
    rest_srv.register_api_handlers(datastore)
    rest_srv.register_static_handlers()

    # Run HTTP server
    rest_srv.run()


if __name__ == "__main__":
    main()
