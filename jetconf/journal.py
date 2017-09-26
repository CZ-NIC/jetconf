from enum import Enum
from colorlog import error, info
from typing import List, Dict

from yangson.enumerations import ContentType, ValidationScope
from yangson.schemanode import SchemaError, SemanticError
from yangson.instvalue import ObjectValue
from yangson.instance import InstanceNode

from . import config
from .helpers import ErrorHelpers, LogHelpers, PathFormat, JsonNodeT
from .errors import ConfHandlerFailedError

epretty = ErrorHelpers.epretty
debug_journal = LogHelpers.create_module_dbg_logger(__name__)


class ChangeType(Enum):
    CREATE = 0,
    REPLACE = 1,
    DELETE = 2


class RpcInfo:
    def __init__(self):
        self.username = None    # type: str
        self.path = None        # type: str
        self.qs = None          # type: Dict[str, List[str]]
        self.path_format = PathFormat.URL   # type: PathFormat
        self.skip_nacm_check = False        # type: bool
        self.op_name = None                 # type: str
        self.op_input_args = None           # type: ObjectValue


class DataChange:
    def __init__(self, change_type: ChangeType, rpc_info: RpcInfo, input_data: JsonNodeT, root_after_change: InstanceNode, nacm_modified: bool):
        self.change_type = change_type
        self.rpc_info = rpc_info
        self.input_data = input_data
        self.root_after_change = root_after_change
        self.nacm_modified = nacm_modified


class UsrChangeJournal:
    def __init__(self, root_origin: InstanceNode):
        self._root_origin = root_origin
        self._journal = []  # type: List[DataChange]

    def get_root_head(self) -> InstanceNode:
        if len(self._journal) > 0:
            return self._journal[-1].root_after_change
        else:
            return self._root_origin

    def get_root_origin(self) -> InstanceNode:
        return self._root_origin

    def add(self, change: DataChange):
        self._journal.append(change)

    def list(self) -> JsonNodeT:
        changes_info = []
        for ch in self._journal:
            changes_info.append([ch.change_type.name, ch.rpc_info.path])

        return changes_info

    def commit(self, ds: "BaseDatastore") -> bool:
        nacm_modified = False

        if len(self._journal) == 0:
            return False

        if hash(ds.get_data_root()) == hash(self._root_origin):
            info("Commiting new configuration (swapping roots)")
            # Set new root
            nr = self.get_root_head()

            for change in self._journal:
                nacm_modified = nacm_modified or change.nacm_modified
        else:
            info("Commiting new configuration (re-applying changes)")
            nr = ds.get_data_root()

            for change in self._journal:
                nacm_modified = nacm_modified or change.nacm_modified

                if change.change_type == ChangeType.CREATE:
                    nr = ds.create_node_rpc(nr, change.rpc_info, change.input_data)[0]
                elif change.change_type == ChangeType.REPLACE:
                    nr = ds.update_node_rpc(nr, change.rpc_info, change.input_data)[0]
                elif change.change_type == ChangeType.DELETE:
                    nr = ds.delete_node_rpc(nr, change.rpc_info)[0]

        try:
            # Validate syntax and semantics of new data
            if config.CFG.glob["VALIDATE_TRANSACTIONS"] is True:
                nr.validate(ValidationScope.all, ContentType.config)
        except (SchemaError, SemanticError) as e:
            error("Data validation error:")
            error(epretty(e))
            raise e

        # Set new data root
        ds.set_data_root(nr)

        # Update NACM if NACM data has been affected by any edit
        if nacm_modified and ds.nacm is not None:
            ds.nacm.update()

        # Call commit begin hook
        begin_hook_failed = False
        try:
            ds.handlers.commit_begin()
        except Exception as e:
            error("Exception occured in commit_begin handler: {}".format(epretty(e)))
            begin_hook_failed = True

        # Run schema node handlers
        conf_handler_failed = False
        if not begin_hook_failed:
            try:
                for change in self._journal:
                    ii = ds.parse_ii(change.rpc_info.path, change.rpc_info.path_format)
                    ds.run_conf_edit_handler(ii, change)
            except Exception as e:
                error("Exception occured in edit handler: {}".format(epretty(e)))
                conf_handler_failed = True

        # Call commit end hook
        end_hook_failed = False
        end_hook_abort_failed = False
        if not (begin_hook_failed or conf_handler_failed):
            try:
                ds.handlers.commit_end(failed=False)
            except Exception as e:
                error("Exception occured in commit_end handler: {}".format(epretty(e)))
                end_hook_failed = True

        if begin_hook_failed or conf_handler_failed or end_hook_failed:
            try:
                # Call commit_end callback again with "failed" argument set to True
                ds.handlers.commit_end(failed=True)
            except Exception as e:
                error("Exception occured in commit_end handler (abort): {}".format(epretty(e)))
                end_hook_abort_failed = True

        # Return to previous version of data and raise an exception if something went wrong
        if begin_hook_failed or conf_handler_failed or end_hook_failed or end_hook_abort_failed:
            ds.data_root_rollback(history_steps=1, store_current=False)

            # Update NACM again after rollback
            if nacm_modified and ds.nacm is not None:
                ds.nacm.update()

            raise ConfHandlerFailedError("(see logged)")

        return True
