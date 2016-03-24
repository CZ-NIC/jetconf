import os
import yaml
from colorlog import warning as warn, info

CONFIG_GLOBAL = {
    "TIMEZONE": "GMT"
}

CONFIG_HTTP = {
    "DOC_ROOT": "doc-root",
    "DOC_DEFAULT_NAME": "index.html",
    "API_ROOT": "/restconf",
    "SERVER_NAME": "hyper-h2",
    "PORT": 8443,

    "SERVER_SSL_CERT": "server.crt",
    "SERVER_SSL_PRIVKEY": "server.key",
    "CA_CERT": "ca.pem"
}

CONFIG_NACM = {
    "ALLOWED_USERS": "lojza@mail.cz"
}

CONFIG = {
    "GLOBAL": CONFIG_GLOBAL,
    "HTTP_SERVER": CONFIG_HTTP,
    "NACM": CONFIG_NACM
}

NACM_ADMINS = CONFIG["NACM"]["ALLOWED_USERS"]
API_ROOT_data = os.path.join(CONFIG_HTTP["API_ROOT"], "data")


def load_config(filename: str):
    global NACM_ADMINS
    global API_ROOT_data

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

    # Shortcuts
    NACM_ADMINS = CONFIG["NACM"]["ALLOWED_USERS"]
    API_ROOT_data = os.path.join(CONFIG_HTTP["API_ROOT"], "data")


def print_config():
    info("Using config:\n" + yaml.dump(CONFIG, default_flow_style=False))
