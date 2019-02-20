import os
import yaml

from colorlog import info
from yaml.parser import ParserError

CFG = None  # type: JcConfig


class JcConfig:
    def __init__(self):
        yang_mod_dir_env = os.environ.get("YANG_MODPATH")

        glob_def = {
            "TIMEZONE": "GMT",
            "LOGFILE": "-",
            "PIDFILE": "/tmp/jetconf.pid",
            "PERSISTENT_CHANGES": True,
            "LOG_LEVEL": "info",
            "LOG_DBG_MODULES": ["*"],
            "YANG_LIB_DIR": yang_mod_dir_env,
            "DATA_JSON_FILE": "data.json",
            "VALIDATE_TRANSACTIONS": True,
            "BACKEND_PACKAGE": "jetconf_jukebox"
        }

        http_def = {
            "DOC_ROOT": "doc-root",
            "DOC_DEFAULT_NAME": "index.html",
            "API_ROOT": "/restconf",
            "SERVER_NAME": "jetconf-h2",
            "UPLOAD_SIZE_LIMIT": 1,
            "LISTEN_LOCALHOST_ONLY": False,
            "PORT": 8443,

            "SERVER_SSL_CERT": "server.crt",
            "SERVER_SSL_PRIVKEY": "server.key",
            "CA_CERT": "ca.pem",
            "DBG_DISABLE_CERTS": False
        }

        nacm_def = {
            "ENABLED": True,
            "ALLOWED_USERS": []
        }

        root_def = {
            "GLOBAL": glob_def,
            "HTTP_SERVER": http_def,
            "NACM": nacm_def
        }

        self.glob = glob_def
        self.http = http_def
        self.nacm = nacm_def
        self.root = root_def

        # Shortcuts
        self.api_root_ds = None
        self.api_root_ops = None
        self.api_root_ylv = None

        self._gen_shortcuts()

    def _gen_shortcuts(self):
        api_root = self.http["API_ROOT"].rstrip("/")
        self.api_root_ds = api_root + "/ds"
        self.api_root_ops = api_root + "/operations"
        self.api_root_ylv = api_root + "/yang-library-version"

    def load_file(self, file_path: str):
        with open(file_path) as conf_fd:
            try:
                conf_yaml = yaml.load(conf_fd)
            except ParserError as e:
                raise ValueError(str(e))

            for conf_key in conf_yaml.keys():
                try:
                    self.root[conf_key].update(conf_yaml[conf_key])
                except KeyError:
                    self.root[conf_key] = {}
                    self.root[conf_key].update(conf_yaml[conf_key])

        self._gen_shortcuts()

    def validate(self):
        if self.glob["YANG_LIB_DIR"] is None:
            raise ValueError("YANG module directory must be specified (in config file or YANG_MODPATH env variable)")

    def print(self):
        info("Using config:\n" + yaml.dump(self.root, default_flow_style=False))
