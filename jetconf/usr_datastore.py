from yangson.datamodel import DataModel

from .data import JsonDatastore


class UserDatastore(JsonDatastore):
    def __init__(self, dm: DataModel, json_file: str, with_nacm: bool = False):
        super().__init__(dm, json_file, with_nacm)
        self.name = "Example Data"
        # Application-specific init actions can be defined here
