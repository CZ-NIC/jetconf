import os
import colorlog
import getopt
import logging
import sys

from pkg_resources import get_distribution, DistributionNotFound
from colorlog import error, info

from . import config, jetconf
from .errors import JetconfInitError


def print_help():
    print("Jetconf command line options:")
    print("-c [config file]        | Pass the configuration file in YAML format")
    print("-v                      | Print version info")
    print("-h                      | Display this help")


def main():
    # Check for Python version
    if sys.version_info < (3, 5):
        print("Jetconf requires Python version 3.5 or higher")
        sys.exit(1)

    # Get Jetconf version
    try:
        jetconf_version = get_distribution("jetconf").version
    except DistributionNotFound:
        jetconf_version = "(not found)"

    # Parse command line arguments
    config_file = "config.yaml"

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
    jc_config = config.JcConfig()
    config.CFG = jc_config

    try:
        jc_config.load_file(config_file)
    except FileNotFoundError:
        print("Configuration file does not exist")
        sys.exit(1)
    except ValueError as e:
        print("Configuration syntax error: " + str(e))
        sys.exit(1)

    # Validate configuration
    try:
        jc_config.validate()
    except ValueError as e:
        print("Error: " + str(e))
        sys.exit(1)
    
    # Set logging level
    log_level = {
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.INFO
    }.get(jc_config.glob["LOG_LEVEL"], logging.INFO)
    logging.root.handlers.clear()

    # Daemonize
    if jc_config.glob["LOGFILE"] not in ("-", "stdout"):
        # Setup basic logging
        logging.basicConfig(
            format="%(asctime)s %(levelname)-8s %(message)s",
            level=log_level,
            filename=jc_config.glob["LOGFILE"]
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
    jc_config.print()

    # Instantiate Jetconf main class
    jc = jetconf.Jetconf(jc_config)
    jetconf.JC = jc

    try:
        jc.init()
    except JetconfInitError as e:
        error(str(e))
        jc.cleanup()

        # Exit
        info("Exiting (error)")
        sys.exit(1)

    # Run Jetconf (this will block until shutdown)
    jc.run()

    jc.cleanup()

    # Exit
    info("Exiting")
    sys.exit(0)


if __name__ == "__main__":
    main()
