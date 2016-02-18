from colorlog import error, warning as warn, info, debug
from typing import List, Any, Dict, TypeVar, Tuple, Callable
import urllib.parse
import re

JsonNodeT = Dict[str, Any]


class PathSegment:
    def __init__(self, segment: str, selector: Tuple[str] = None, ns: str = None):
        self.val = segment
        self.select = selector
        self.ns = ns

    def get_val(self, fully_qualified=False) -> str:
        ns = (self.ns + ":") if (fully_qualified and self.ns) else ""
        return ns + self.val

    def __repr__(self):
        ns = (self.ns + ":") if self.ns else ""
        sel = "[{}='{}']".format(self.select[0], self.select[1]) if self.select else ""
        return ns + self.val + sel

    def __eq__(self, other):
        return (self.val == other.val) and (self.select == other.select) and (self.ns == other.ns)

    def __ne__(self, other):
        return not self.__eq__(other)


class BasePath:
    def __init__(self, path: str, segment_parser: Callable[[str], PathSegment] = None):
        self.path_str = path
        self.path_segments = []  # type: List[PathSegment]
        self._is_absolute = False

        if self.path_str[0] == "/":
            self._is_absolute = True
            self.path_str = self.path_str[1:]

        _segments = filter(lambda x: len(x) > 0, self.path_str.split("/"))
        if segment_parser is not None:
            self.path_segments = list(map(segment_parser, _segments))
        else:
            self.path_segments = list(map(lambda x: PathSegment(x), _segments))

    def is_absolute(self) -> bool:
        return self._is_absolute

    def path_contains(self, subpath) -> bool:
        if subpath[0] == "/":
            subpath = subpath[1:]
            return (self.path_str == subpath) or (
                (len(self.path_str) > len(subpath)) and self.path_str.startswith(subpath) and (
                    self.path_str[len(subpath)] == "/"))
        else:
            return self.path_str.find(subpath) != -1

    def path_equals(self, path_to_compare: str) -> bool:
        if (path_to_compare[0] == "/") and self._is_absolute:
            return self.path_str.strip("/") == path_to_compare.strip("/")
        elif (path_to_compare[0] != "/") and not self._is_absolute:
            return self.path_str.rstrip("/") == path_to_compare.rstrip("/")
        else:
            return False


class URLPath(BasePath):
    def __init__(self, url_path: str):
        self.query_string = None
        self.query_table = None
        _last_ns = None

        if url_path.find("?") != -1:
            self.path_str, self.query_string = url_path.split("?", 1)
        else:
            self.path_str = url_path

        path_str_unquoted = urllib.parse.unquote(self.path_str)

        def parse_segment(s: str) -> PathSegment:
            nonlocal _last_ns
            sre_match = re.search("^(?:([\w-]*?):)?([\w-]*)(?:=(.+))?$", s)
            if sre_match is None:
                raise ValueError("Wrong formatting of path segment: {}".format(s))
            else:
                if sre_match.group(1) is not None:
                    _last_ns = sre_match.group(1)
                # elif _last_ns is None and sre_match.group(2) != "":
                #     raise ValueError("First segment of path must be in namespace-qualified form")

                return PathSegment(sre_match.group(2), ("name", sre_match.group(3)) if sre_match.group(3) else None,
                                   _last_ns)

        super().__init__(path_str_unquoted, parse_segment)
        print(self.path_segments)

        if self.query_string:
            self.query_table = urllib.parse.parse_qs(self.query_string, keep_blank_values=True)


# Parses path in "Yang Json" format as defined in
# https://tools.ietf.org/html/draft-ietf-netmod-yang-json-07#section-6.11
class YangJsonPath(BasePath):
    def __init__(self, path: str):
        _last_ns = None

        def parse_segment(s: str) -> PathSegment:
            nonlocal _last_ns
            sre_match = re.search("^(?:([\w-]*?):)?([\w-]*)(?:\[(.+)\])?$", s)
            if sre_match is None:
                raise ValueError("Wrong formatting of path segment: {}".format(s))
            else:
                if sre_match.group(1) is not None:
                    _last_ns = sre_match.group(1)
                elif _last_ns is None and sre_match.group(2) != "":
                    raise ValueError(
                            "First segment of path must be in namespace-qualified form, see draft-ietf-netmod-yang-json-07")

                return PathSegment(sre_match.group(2), tuple(
                        map(lambda x: x.strip("'\""), sre_match.group(3).split("="))) if sre_match.group(3) else None,
                                   _last_ns)

        super().__init__(path, parse_segment)
        # print(self.segments)
