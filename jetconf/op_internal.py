from .config import CONFIG
from .helpers import JsonNodeT
from .handler_list import OP_HANDLERS
from .data import BaseDatastore, RpcInfo, StagingDataException


class OpHandlersContainer:
    def __init__(self, ds: BaseDatastore):
        self.ds = ds

    def jetconf_conf_start(self, rpc: RpcInfo) -> JsonNodeT:
        # try:
        #     transaction_opts = rpc.op_input_args["options"]
        # except (TypeError, KeyError):
        #     transaction_opts = None
        # self.ds.make_user_journal(rpc.username, transaction_opts)
        self.ds.make_user_journal(rpc.username, None)
        ret_data = {"status": "OK"}

        return ret_data

    def jetconf_conf_status(self, rpc: RpcInfo) -> JsonNodeT:
        try:
            usr_journal = self.ds.get_user_journal(rpc.username)
            transaction_opened = True
        except StagingDataException:
            transaction_opened = False

        ret_data = {
            "status": "OK",
            "transaction-opened": transaction_opened
        }

        return ret_data

    def jetconf_conf_reset(self, rpc: RpcInfo) -> JsonNodeT:
        self.ds.drop_user_journal(rpc.username)
        ret_data = {"status": "OK"}
        return ret_data

    def jetconf_conf_commit(self, rpc: RpcInfo) -> JsonNodeT:
        try:
            usr_journal = self.ds.get_user_journal(rpc.username)
        except StagingDataException:
            usr_journal = None

        if usr_journal is not None:
            try:
                self.ds.lock_data(rpc.username)
                commit_res = usr_journal.commit(self.ds)
                if CONFIG["GLOBAL"]["PERSISTENT_CHANGES"] is True:
                    self.ds.save()
            finally:
                self.ds.unlock_data()

            self.ds.drop_user_journal(rpc.username)
        else:
            commit_res = False

        ret_data = {
            "status": "OK",
            "conf-changed": commit_res
        }

        return ret_data

    def jetconf_get_schema_digest(self, rpc: RpcInfo) -> JsonNodeT:
        ret_data = self.ds.get_dm().schema_digest()
        return ret_data

    def jetconf_get_list_length(self, rpc: RpcInfo) -> JsonNodeT:
        try:
            list_url = rpc.op_input_args["url"]  # type: str
        except (TypeError, KeyError):
            raise ValueError("This operation expects \"url\" input parameter")

        try:
            staging = rpc.op_input_args["staging"]  # type: str
        except (TypeError, KeyError):
            staging = False

        rpc_gll = RpcInfo()
        rpc_gll.username = rpc.username
        rpc_gll.skip_nacm_check = rpc.skip_nacm_check
        rpc_gll.path = list_url.rstrip("/")
        rpc_gll.qs = {}

        ln_val = self.ds.get_node_rpc(rpc_gll, staging).value

        if isinstance(ln_val, list):
            ret_data = {"jetconf:list-length": len(ln_val)}
        else:
            raise ValueError("Passed URI does not point to List")

        return ret_data


def register_op_handlers(ds: BaseDatastore):
    op_handlers_obj = OpHandlersContainer(ds)
    # OP_HANDLERS.register(op_handlers_obj.jetconf_conf_start, "jetconf:conf-start")
    OP_HANDLERS.register(op_handlers_obj.jetconf_conf_status, "jetconf:conf-status")
    OP_HANDLERS.register(op_handlers_obj.jetconf_conf_reset, "jetconf:conf-reset")
    OP_HANDLERS.register(op_handlers_obj.jetconf_conf_commit, "jetconf:conf-commit")
    OP_HANDLERS.register(op_handlers_obj.jetconf_get_schema_digest, "jetconf:get-schema-digest")
    OP_HANDLERS.register(op_handlers_obj.jetconf_get_list_length, "jetconf:get-list-length")
