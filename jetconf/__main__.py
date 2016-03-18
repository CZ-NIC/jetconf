import colorlog
import getopt
import logging
import sys

from importlib import import_module
from . import rest_server


def main():
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
        # except AttributeError:
        #     print("Module \"{}\" has no test() function".format(test_module))

    else:
        rest_server.run()


if __name__ == "__main__":
    main()
