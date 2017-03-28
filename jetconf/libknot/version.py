import os
import re

from typing import Tuple


def get_knot_version() -> Tuple[int, int]:
    fp = os.popen("knotd --version 2>/dev/null")
    knotd_resp = fp.read()
    ret_close = fp.close()

    if ret_close is not None:
        raise ValueError("Cannot determine KnotDNS version. Is 'knotd --version' command functional?")

    # 'knotd (Knot DNS), version 2.4.0-dev\n'

    try:
        ver_major_minor = re.findall("version (\d+)\.(\d+)", knotd_resp)[0]
    except IndexError:
        raise ValueError("Cannot determine KnotDNS version. Unknown data received from 'knotd --version'")

    ver_major_minor_int = tuple(map(lambda n: int(n), ver_major_minor))
    return ver_major_minor_int
