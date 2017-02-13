from enum import Enum
from typing import Dict, List
from colorlog import error, warning as warn, info

from . import knot_api
from .helpers import JsonNodeT
from .knot_api import SOARecord, ARecord, AAAARecord, MXRecord


class KnotZoneCmd(Enum):
    SET = 0
    UNSET = 1


class KnotOp:
    def __init__(self, cmd: KnotZoneCmd, op_input: JsonNodeT):
        self.cmd = cmd
        self.op_input = op_input


class OpHandlersContainer:
    def __init__(self):
        self.op_journal = {}     # type: Dict[str, List[KnotOp]]

    def zone_begin_transaction(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        self.op_journal[username] = []

    def zone_commit_transaction(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        try:
            usr_op_journal = self.op_journal[username]
        except KeyError:
            warn("zone_commit_transaction: Nothing to commit")
            return

        # Connect to Knot socket and start zone transaction
        knot_api.KNOT.knot_connect()
        knot_api.KNOT.begin_zone()

        for knot_op in usr_op_journal:
            input_args = knot_op.op_input
            domain = input_args["dns-zone-rpcs:zone"]
            if knot_op.cmd == KnotZoneCmd.SET:
                rr_type = input_args["dns-zone-rpcs:type"][0]
                if rr_type == "SOA":
                    rrdata = input_args["dns-zone-rpcs:SOA"]
                    rr = SOARecord()
                    rr.ttl = input_args["dns-zone-rpcs:ttl"]
                    rr.mname = rrdata["mname"]
                    rr.rname = rrdata["rname"]
                    rr.serial = rrdata["serial"]
                    rr.refresh = rrdata["refresh"]
                    rr.retry = rrdata["retry"]
                    rr.expire = rrdata["expire"]
                    rr.minimum = rrdata["minimum"]
                    knot_api.KNOT.zone_add_record(domain, rr)
                elif rr_type == "A":
                    rrdata = input_args["dns-zone-rpcs:A"]
                    rr = ARecord(input_args["dns-zone-rpcs:owner"], input_args["dns-zone-rpcs:ttl"])
                    rr.address = rrdata["address"]
                    knot_api.KNOT.zone_add_record(domain, rr)
                elif rr_type == "AAAA":
                    rrdata = input_args["dns-zone-rpcs:AAAA"]
                    rr = AAAARecord(input_args["dns-zone-rpcs:owner"], input_args["dns-zone-rpcs:ttl"])
                    rr.address = rrdata["address"]
                    knot_api.KNOT.zone_add_record(domain, rr)
                elif rr_type == "MX":
                    rrdata = input_args["dns-zone-rpcs:MX"]
                    rr = MXRecord(input_args["dns-zone-rpcs:owner"], input_args["dns-zone-rpcs:ttl"])
                    rr.address = rrdata["address"]
                    knot_api.KNOT.zone_add_record(domain, rr)

            elif knot_op.cmd == KnotZoneCmd.UNSET:
                pass

        knot_api.KNOT.commit()
        knot_api.KNOT.knot_disconnect()
        del self.op_journal[username]

    def zone_abort_transaction(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        try:
            del self.op_journal[username]
        except KeyError:
            warn("zone_abort_transaction: Nothing to abort")

    def zone_set(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        try:
            usr_op_journal = self.op_journal[username]
        except KeyError:
            warn("zone_set: Op transaction not started")
            return

        usr_op_journal.append(KnotOp(KnotZoneCmd.SET, input_args))

    def zone_unset(self, input_args: JsonNodeT, username: str) -> JsonNodeT:
        try:
            usr_op_journal = self.op_journal[username]
        except KeyError:
            warn("zone_set: Op transaction not started")
            return

        usr_op_journal.append(KnotOp(KnotZoneCmd.UNSET, input_args))


OP_HANDLERS_IMPL = OpHandlersContainer()
