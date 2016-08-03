from typing import Dict, Any

JsonNodeT = Dict[str, Any]


def play_op_handler(input_args: JsonNodeT) -> JsonNodeT:
    print("Playing song {} in playlist \"{}\"".format(input_args.get("song-number"), input_args.get("playlist")))
    ret = {"status": "OK"}
    return ret