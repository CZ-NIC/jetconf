"""Python libknot interface."""

from .version import get_knot_version

knot_ver = get_knot_version()
if knot_ver < (2, 4):
    raise ValueError(
        "Installed version of KnotDNS is too old (found: {}.{}). libknot-python only supports KnotDNS version 2.4 and higher.".format(
            knot_ver[0],
            knot_ver[1]
        )
    )
