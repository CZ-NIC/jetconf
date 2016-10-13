import os
import yaml

from yaml.parser import ParserError
from colorlog import error, warning as warn, info

CONFIG_GLOBAL = {
    "TIMEZONE": "GMT",
    "LOGFILE": "-",
    "PIDFILE": "/tmp/jetconf.pid",
    "PERSISTENT_CHANGES": True,
    "LOG_LEVEL": "info",
    "LOG_DBG_MODULES": ["*"]
}

CONFIG_HTTP = {
    "DOC_ROOT": "doc-root",
    "DOC_DEFAULT_NAME": "index.html",
    "API_ROOT": "/restconf",
    "API_ROOT_STAGING": "/restconf_staging",
    "SERVER_NAME": "hyper-h2",
    "UPLOAD_SIZE_LIMIT": 1,
    "PORT": 8443,

    "SERVER_SSL_CERT": "server.crt",
    "SERVER_SSL_PRIVKEY": "server.key",
    "CA_CERT": "ca.pem",
    "DBG_DISABLE_CERTS": False
}

CONFIG_NACM = {
    "ALLOWED_USERS": "lojza@mail.cz"
}

CONFIG_KNOT = {
    "SOCKET": "/tmp/knot.sock"
}

CONFIG = {
    "GLOBAL": CONFIG_GLOBAL,
    "HTTP_SERVER": CONFIG_HTTP,
    "NACM": CONFIG_NACM,
    "KNOT": CONFIG_KNOT
}

NACM_ADMINS = CONFIG["NACM"]["ALLOWED_USERS"]
API_ROOT_data = os.path.join(CONFIG_HTTP["API_ROOT"], "data")
API_ROOT_STAGING_data = os.path.join(CONFIG_HTTP["API_ROOT_STAGING"], "data")
API_ROOT_ops = os.path.join(CONFIG_HTTP["API_ROOT"], "operations")


def load_config(filename: str):
    global NACM_ADMINS
    global API_ROOT_data
    global API_ROOT_STAGING_data
    global API_ROOT_ops

    try:
        with open(filename) as conf_fd:
            conf_yaml = yaml.load(conf_fd)
            for conf_key in CONFIG.keys():
                try:
                    CONFIG[conf_key].update(conf_yaml[conf_key])
                except KeyError:
                    pass

    except FileNotFoundError:
        warn("Configuration file does not exist")
    except ParserError as e:
        error("Configuration syntax error: " + str(e))
        exit()

    # Shortcuts
    NACM_ADMINS = CONFIG["NACM"]["ALLOWED_USERS"]
    API_ROOT_data = os.path.join(CONFIG_HTTP["API_ROOT"], "data")
    API_ROOT_STAGING_data = os.path.join(CONFIG_HTTP["API_ROOT_STAGING"], "data")
    API_ROOT_ops = os.path.join(CONFIG_HTTP["API_ROOT"], "operations")


def print_config():
    info("Using config:\n" + yaml.dump(CONFIG, default_flow_style=False))
