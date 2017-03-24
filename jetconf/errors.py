# Base class for all exceptions defined in jetconf
class JetconfError(Exception):
    def __init__(self, msg=""):
        self.msg = msg

    def __str__(self):
        return self.msg
