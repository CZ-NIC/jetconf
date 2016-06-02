import colorlog
import getopt
import logging
import sys

from importlib import import_module
from yangson.instance import InstancePath
from . import usr_op_handlers, usr_state_data_handlers
from .rest_server import RestServer
from .config import load_config, print_config
from .nacm import NacmConfig
from .data import JsonDatastore, BaseDataListener, SchemaNode
from .helpers import DataHelpers
from .handler_list import OP_HANDLERS, STATE_DATA_HANDLES


class MyInfoDataListener(BaseDataListener):
    def process(self, sn: SchemaNode, ii: InstancePath):
        print("Change at sn \"{}\", dn \"{}\"".format(sn.name, ii))


def main():
    # Load configuration
    load_config("jetconf/config.yaml")
    print_config()

    # Load data model
    datamodel = DataHelpers.load_data_model("data/", "data/yang-library-data.json")

    # NACM init
    nacm_data = JsonDatastore(datamodel, "NACM data")
    nacm_data.load("jetconf/example-data-nacm.json")

    nacmc = NacmConfig(nacm_data)

    # Datastore init
    ex_datastore = JsonDatastore(datamodel, "DNS data")
    ex_datastore.load("jetconf/example-data.json")
    ex_datastore.register_nacm(nacmc)
    nacmc.set_ds(ex_datastore)

    # Register schema listeners
    zone_listener1 = MyInfoDataListener(ex_datastore)
    zone_listener1.add_schema_node("/dns-server:dns-server/zones")
    zone_listener1.add_schema_node("/ietf-netconf-acm:nacm/rule-list/rule")

    # Register op handlers
    OP_HANDLERS.register_handler("generate-key", usr_op_handlers.sign_op_handler)

    # Create and register state data handlers
    # usr_state_data_handlers.create_zone_state_handlers(STATE_DATA_HANDLES, datamodel)

    # Create HTTP server
    rest_srv = RestServer()
    rest_srv.register_api_handlers(ex_datastore)
    rest_srv.register_static_handlers()

    # Run HTTP server
    rest_srv.run()


if __name__ == "__main__":
    opts, args = (None, None)

    colorlog.basicConfig(
        format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(message)s",
        level=logging.INFO,
        stream=sys.stdout
    )

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
