from yangson.instance import InstanceRoute, NonexistentInstance


# Base class for all exceptions defined in jetconf
class JetconfError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg


class BackendError(JetconfError):
    pass


class StateNonexistentInstance(NonexistentInstance):
    def __init__(self, ii: InstanceRoute, text: str) -> None:
        self.ii = ii
        self.text = text

    def __str__(self):
        return str(self.ii) + ": " + self.text
