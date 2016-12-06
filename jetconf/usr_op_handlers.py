from .helpers import JsonNodeT


def sign_op_handler(input_args: JsonNodeT) -> JsonNodeT:
    print("input={}".format(input_args))
    print("signing...")
    ret = {"status": "OK"}
    return ret
