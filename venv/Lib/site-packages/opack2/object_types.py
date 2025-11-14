import copy
import datetime
import struct
from enum import Enum, auto
from typing import Tuple

from opack2.exceptions import BytesTooLargeError, IntegerOutOfBoundsError, InvalidTypeError


class TerminatorObject:
    """Used to imitate the \x03 terminator in the construct struct"""
    pass


def _get_bool_object_type(obj) -> int:
    if obj:
        return 1
    return 2


def _get_set_object_type(obj) -> int:
    return 3


def _get_datetime_object_time(obj) -> int:
    return 6


def _get_int_object_type(obj) -> int:
    if obj < 0:
        return _get_float_object_type(obj)
    elif obj <= 0x27:
        return obj + 8
    elif obj.bit_length() <= 8:
        return 0x30
    elif obj.bit_length() <= 32:
        return 0x32
    elif obj.bit_length() <= 64:
        return 0x33
    raise IntegerOutOfBoundsError(f'{obj} is too big for uint64_t')


def _get_float_object_type(obj) -> int:
    if struct.unpack('f', struct.pack('f', obj))[0] == obj:  # check if the number fits in a c float
        return 0x35
    else:
        return 0x36


def _get_str_object_type(obj) -> int:
    obj_len = len(obj.encode())
    if obj_len <= 0x20:
        return 0x40 + obj_len
    elif obj_len <= 0xFF:
        return 0x61
    elif obj_len <= 0xFFFF:
        return 0x62
    elif obj_len < 2 ** 32:
        return 0x63
    return 0x64


def _get_bytes_object_type(obj) -> int:
    obj_len = len(obj)
    if obj_len <= 0x20:
        return 0x70 + obj_len
    elif obj_len <= 0xFF:
        return 0x91
    elif obj_len <= 0xFFFF:
        return 0x92
    elif obj_len < 2 ** 32:
        return 0x93
    elif obj_len < 2 ** 64:
        return 0x94
    raise BytesTooLargeError(f'bytes are too large ({obj_len})')


def _get_list_object_type(obj) -> int:
    if len(obj) < 15:
        return 0xD0 + len(obj)
    else:
        obj = copy.copy(obj)
        obj.append(TerminatorObject())
        return 0xDF, obj


def _get_dict_object_type(obj) -> Tuple[int, list]:
    obj_len = len(obj)
    obj = list(obj.items())
    if obj_len < 15:
        return 0xE0 + obj_len, obj
    else:
        obj.append((TerminatorObject(), TerminatorObject()))
        return 0xEF, obj


OBJ_TYPE_MAP = {
    bool: _get_bool_object_type, datetime.datetime: _get_datetime_object_time, TerminatorObject: _get_set_object_type,
    int: _get_int_object_type, float: _get_float_object_type, str: _get_str_object_type,
    bytes: _get_bytes_object_type, list: _get_list_object_type, dict: _get_dict_object_type
}


class OPackObjectType(Enum):
    BOOL = auto()
    TERMINATOR = auto()
    TIMESTAMP = auto()
    INT = auto()
    STRING = auto()
    BYTES = auto()
    ARRAY_LENGTHED = auto()
    ARRAY_TERMINATED = auto()
    DICT_LENGTHED = auto()
    DICT_TERMINATED = auto()

    @staticmethod
    def get_type(obj_type) -> 'OPackObjectType':
        if obj_type == 1 or obj_type == 2:
            return OPackObjectType.BOOL
        if obj_type == 3:
            return OPackObjectType.TERMINATOR
        if obj_type == 6:
            return OPackObjectType.TIMESTAMP
        if 8 <= obj_type <= 0x36 and obj_type != 0x31 and obj_type != 0x34:
            return OPackObjectType.INT
        if 0x40 <= obj_type <= 0x64:
            return OPackObjectType.STRING
        if 0x70 <= obj_type <= 0x94:
            return OPackObjectType.BYTES
        if 0xD0 <= obj_type <= 0xDF:
            if obj_type == 0xDF:
                return OPackObjectType.ARRAY_TERMINATED
            return OPackObjectType.ARRAY_LENGTHED
        if 0xE0 <= obj_type <= 0xEF:
            if obj_type == 0xEF:
                return OPackObjectType.DICT_TERMINATED
            return OPackObjectType.DICT_LENGTHED
        raise InvalidTypeError(f'Invalid object type: {obj_type}')
