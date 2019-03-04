from yangson.instance import InstanceRoute, NonexistentInstance


# Base class for all exceptions defined in jetconf
class JetconfError(Exception):
    def __init__(self, msg: str = ""):
        self.msg = msg


# Jetconf errors
class JetconfInitError(JetconfError):
    pass


class BackendError(JetconfError):
    pass


class DataLockError(JetconfError):
    pass


class StagingDataException(JetconfError):
    pass


class InstanceAlreadyPresent(JetconfError):
    pass


# Handler errors
class HandlerError(JetconfError):
    pass


class NoHandlerError(HandlerError):
    pass


class ConfHandlerFailedError(HandlerError):
    pass


class OpHandlerFailedError(HandlerError):
    pass


class NoHandlerForOpError(NoHandlerError):
    def __init__(self, op_name: str):
        self.op_name = op_name

    def __str__(self):
        return "Nonexistent handler for operation \"{}\"".format(self.op_name)


class NoHandlerForStateDataError(NoHandlerError):
    pass


class StateNonexistentInstance(NonexistentInstance):
    def __init__(self, ii: InstanceRoute, text: str) -> None:
        self.ii = ii
        self.text = text

    def __str__(self):
        return str(self.ii) + ": " + self.text


# NACM errors
class NacmError(JetconfError):
    pass


class NonexistentUserError(NacmError):
    pass


class NacmForbiddenError(NacmError):
    def __init__(self, msg="Access to data node rejected by NACM", rule=None):
        self.msg = msg
        self.rule = rule

    def __str__(self):
        return "{} (rule: {})".format(self.msg, str(self.rule))
