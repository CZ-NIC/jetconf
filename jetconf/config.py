import os
import yaml

from colorlog import info

CONFIG_GLOBAL = {
    "TIMEZONE": "GMT",
    "LOGFILE": "-",
    "PIDFILE": "/tmp/jetconf.pid",
    "PERSISTENT_CHANGES": True,
    "LOG_LEVEL": "info",
    "LOG_DBG_MODULES": ["*"],
    "YANG_LIB_DIR": "yang-data/",
    "DATA_JSON_FILE": "data.json",
    "VALIDATE_TRANSACTIONS": True
}

CONFIG_HTTP = {
    "DOC_ROOT": "doc-root",
    "DOC_DEFAULT_NAME": "index.html",
    "API_ROOT": "/restconf",
    "API_ROOT_STAGING": "/restconf_staging",
    "SERVER_NAME": "jetconf-h2",
    "UPLOAD_SIZE_LIMIT": 1,
    "LISTEN_LOCALHOST_ONLY": False,
    "AC_ALLOW_ORIGIN": "http://localhost:3000",
    "AC_ALLOW_METHODS": "POST, GET, OPTIONS, PUT, DELETE",
    "PORT": 8443,

    "SERVER_SSL_CERT": "server.crt",
    "SERVER_SSL_PRIVKEY": "server.key",
    "CA_CERT": "ca.pem",
    "DBG_DISABLE_CERTS": False
}

CONFIG_NACM = {
    "ENABLED": True,
    "ALLOWED_USERS": []
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

API_ROOT_data = os.path.join(CONFIG_HTTP["API_ROOT"], "data")
API_ROOT_STAGING_data = os.path.join(CONFIG_HTTP["API_ROOT_STAGING"], "data")
API_ROOT_ops = os.path.join(CONFIG_HTTP["API_ROOT"], "operations")
API_ROOT_ylv = os.path.join(CONFIG_HTTP["API_ROOT"], "yang-library-version")


def load_config(filename: str) -> bool:
    global API_ROOT_data
    global API_ROOT_STAGING_data
    global API_ROOT_ops
    global API_ROOT_ylv

    with open(filename) as conf_fd:
        conf_yaml = yaml.load(conf_fd)
        for conf_key in CONFIG.keys():
            try:
                CONFIG[conf_key].update(conf_yaml[conf_key])
            except KeyError:
                pass

    # Shortcuts
    API_ROOT_data = os.path.join(CONFIG_HTTP["API_ROOT"], "data")
    API_ROOT_STAGING_data = os.path.join(CONFIG_HTTP["API_ROOT_STAGING"], "data")
    API_ROOT_ops = os.path.join(CONFIG_HTTP["API_ROOT"], "operations")
    API_ROOT_ylv = os.path.join(CONFIG_HTTP["API_ROOT"], "yang-library-version")


def print_config():
    info("Using config:\n" + yaml.dump(CONFIG, default_flow_style=False))
