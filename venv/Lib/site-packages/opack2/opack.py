from typing import Mapping

from opack2.opack_construct import OPack


def loads(opack_bytes: bytes) -> Mapping:
    return OPack.parse(opack_bytes).value


def dumps(obj) -> bytes:
    return OPack.build(obj)
