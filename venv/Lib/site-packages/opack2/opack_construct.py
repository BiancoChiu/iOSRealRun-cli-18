from typing import List, Mapping

from construct import Adapter, Array, Computed, Filter, Float32l, Float64l, GreedyBytes, GreedyString, Int8ub, Int8ul, \
    Int16ub, Int32ub, Int32ul, Int64ub, Int64ul, LazyBound, PascalString, Prefixed, RepeatUntil, Struct, Switch, \
    Timestamp, this

from opack2.object_types import OBJ_TYPE_MAP, OPackObjectType, TerminatorObject


class ArrayAdapter(Adapter):
    def _decode(self, obj, context, path) -> List:
        arr = []
        for element in obj:
            arr.append(element.value)
        return arr

    def _encode(self, obj, context, path):
        return obj


class DictionaryAdapter(Adapter):
    def _decode(self, obj, context, path) -> Mapping:
        dictionary = {}
        for dict_obj in obj:
            dictionary[dict_obj.key.value] = dict_obj.value.value
        return dictionary

    def _encode(self, obj, context, path) -> List:
        encoded_dict = []
        for key, val in obj:
            encoded_dict.append({'key': key, 'value': val})  # this is the format OPackObjectAdapter expects
        return encoded_dict


class OPackObjectAdapter(Adapter):
    def _decode(self, obj, context, path):
        return obj

    def _encode(self, obj, context, path) -> Mapping:
        for type in OBJ_TYPE_MAP:
            if isinstance(obj, type):
                obj_type = OBJ_TYPE_MAP[type](obj)
                if isinstance(obj_type, tuple):
                    obj_type, obj = obj_type
                break
        return {"type": obj_type, "value": obj}  # this is the format OPackObjectAdapter expects


BoolOPack = Switch(this.type, {1: Computed(True), 2: Computed(False)})
TerminatorOPack = Computed(None)
TimestampOPack = Timestamp(Float64l, 1, 1904)  # MacOS starting time
IntOPack = Switch(this.type, {0x30: Int8ul, 0x32: Int32ul, 0x33: Int64ul, 0x35: Float32l, 0x36: Float64l},
                  default=Computed(this.type - 8))
StringOPack = Switch(this.type, {0x61: PascalString(Int8ub, 'utf8'), 0x62: PascalString(Int16ub, 'utf8'),
                                 0x63: PascalString(Int32ub, 'utf8'), 0x64: PascalString(Int64ub, 'utf8')},
                     default=Prefixed(Computed(this.type - 0x40), GreedyString('utf8')))
BytesOPack = Switch(this.type, {0x91: Prefixed(Int8ub, GreedyBytes), 0x92: Prefixed(Int16ub, GreedyBytes),
                                0x93: Prefixed(Int32ub, GreedyBytes),
                                0x94: Prefixed(Int64ub, GreedyBytes)},
                    default=Prefixed(Computed(this.type - 0x70), GreedyBytes))

ArrayLengthedOPack = ArrayAdapter(Array(this.type - 0xD0, LazyBound(lambda: OPack)))

ArrayOPackFilter = Filter(lambda obj, ctx: not hasattr(obj, 'type') or obj.type != 3,
                          RepeatUntil(lambda obj, lst, ctx: obj.type == 3
                          if hasattr(obj, 'type') else isinstance(obj, TerminatorObject),
                                      LazyBound(lambda: OPack)))

ArrayTerminatedOPack = ArrayAdapter(ArrayOPackFilter)

DictionaryLengthedOPack = DictionaryAdapter(Array(this.type - 0xE0,
                                                  Struct('key' / LazyBound(lambda: OPack),
                                                         'value' / LazyBound(lambda: OPack))))

DictionaryOPackFilter = Filter(lambda obj, ctx: not hasattr(obj, 'key') or obj.key.type != 3,
                               RepeatUntil(lambda obj, lst, ctx: obj.key.type == 3
                               if hasattr(obj, 'key') else isinstance(obj['key'], TerminatorObject),
                                           Struct('key' / LazyBound(lambda: OPack),
                                                  'value' / LazyBound(lambda: OPack))))

DictionaryTerminatedOPack = DictionaryAdapter(DictionaryOPackFilter)

OPack = OPackObjectAdapter(Struct(
    'type' / Int8ub,
    'value' / Switch(lambda ctx: OPackObjectType.get_type(ctx.type), {
        OPackObjectType.BOOL: BoolOPack, OPackObjectType.TERMINATOR: TerminatorOPack,
        OPackObjectType.TIMESTAMP: TimestampOPack, OPackObjectType.INT: IntOPack,
        OPackObjectType.STRING: StringOPack, OPackObjectType.BYTES: BytesOPack,
        OPackObjectType.ARRAY_LENGTHED: ArrayLengthedOPack,
        OPackObjectType.ARRAY_TERMINATED: ArrayTerminatedOPack, OPackObjectType.DICT_LENGTHED: DictionaryLengthedOPack,
        OPackObjectType.DICT_TERMINATED: DictionaryTerminatedOPack
    })
))
