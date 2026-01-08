"""
Module to wrap an integer in bitwise flag/field accessors.
"""

from collections import OrderedDict
from collections.abc import Iterable

from pcapng._compat import namedtuple


class FlagBase(object):
    """\
    Base class for flag types to be used in a Flags object.
    Handles the bitwise math so subclasses don't have to worry about it.
    """

    __slots__ = [
        "owner",
        "offset",
        "size",
        "extra",
        "mask",
    ]

    def __init__(self, owner, offset, size, extra=None):
        if size < 1:
            raise TypeError("Flag must be at least 1 bit wide")
        if size > owner._nbits:
            raise TypeError("Flag must fit into owner size")
        self.owner = owner
        self.offset = offset
        self.size = size
        self.extra = extra
        self.mask = ((1 << self.size) - 1) << self.offset

    def get_bits(self):
        return (self.owner._value & self.mask) >> self.offset

    def set_bits(self, val):
        val &= (1 << self.size) - 1
        self.owner._value &= ~self.mask
        self.owner._value |= val << self.offset


class FlagBool(FlagBase):
    """Object representing a single boolean flag"""

    def __init__(self, owner, offset, size, extra=None):
        if size != 1:
            raise TypeError(
                "{cls} can only be 1 bit in size".format(cls=self.__class__.__name__)
            )
        super(FlagBool, self).__init__(owner, offset, size)

    def get(self):
        return bool(self.get_bits())

    def set(self, val):
        self.set_bits(int(bool(val)))


class FlagUInt(FlagBase):
    """\
    Object representing an unsigned integer of the given size stored in
    a larger bitfield
    """

    def get(self):
        return self.get_bits()

    def set(self, val):
        self.set_bits(val)


class FlagEnum(FlagBase):
    """\
    Object representing a range of values stored in part of a larger
    bitfield
    """

    def __init__(self, owner, offset, size, extra=None):
        if not isinstance(extra, Iterable):
            raise TypeError(
                "{cls} needs an iterable of values".format(cls=self.__class__.__name__)
            )
        extra = list(extra)
        if len(extra) > 2**size:
            raise TypeError(
                "{cls} iterable has too many values (got {got}, "
                "{size} bits only address {max})".format(
                    cls=self.__class__.__name__,
                    got=len(extra),
                    size=size,
                    max=2**size,
                )
            )

        super(FlagEnum, self).__init__(owner, offset, size, extra)

    def get(self):
        val = self.get_bits()
        try:
            return self.extra[val]
        except IndexError:
            return "[invalid value]"

    def set(self, val):
        if val in self.extra:
            self.set_bits(self.extra.index(val))
        elif isinstance(val, int):
            self.set_bits(val)
        else:
            raise TypeError(
                "Invalid value {val} for {cls}".format(
                    val=val, cls=self.__class__.__name__
                )
            )


# Class representing a single flag schema for FlagWord.
# 'nbits' defaults to 1, and 'extra' defaults to None.
FlagField = namedtuple(
    "FlagField", ("name", "ftype", "nbits", "extra"), defaults=(1, None)
)


class FlagWord(object):
    """\
    Class to wrap an integer in bitwise flag/field accessors.
    """

    __slots__ = [
        "_nbits",
        "_value",
        "_schema",
    ]

    def __init__(self, schema, nbits=32, initial=0):
        """
        :param schema:
            A list of FlagField objects representing the values to be packed
            into this object, in order from LSB to MSB of the underlying int

        :param nbits:
            An integer representing the total number of bits used for flags

        :param initial:
            The initial integer value of the flags field
        """

        self._nbits = nbits
        self._value = initial
        self._schema = OrderedDict()

        tot_bits = sum([item.nbits for item in schema])
        if tot_bits > nbits:
            raise TypeError(
                "Too many fields for {nbits}-bit field "
                "(schema defines {tot} bits)".format(nbits=nbits, tot=tot_bits)
            )

        bitn = 0
        for item in schema:
            if not isinstance(item, FlagField):
                raise TypeError("Schema must be composed of FlagField objects")
            if not issubclass(item.ftype, FlagBase):
                raise TypeError("Expected FlagBase, got {}".format(item.ftype))
            self._schema[item.name] = item.ftype(self, bitn, item.nbits, item.extra)
            bitn += item.nbits

    def __int__(self):
        return self._value

    def __repr__(self):
        rv = "<{0} (value={1})".format(self.__class__.__name__, self._value)
        for k, v in self._schema.items():
            rv += " {0}={1}".format(k, v.get())
        return rv + ">"

    def __getattr__(self, name):
        try:
            v = self._schema[name]
        except KeyError:
            raise AttributeError(name)
        return v.get()

    def __setattr__(self, name, val):
        try:
            return object.__setattr__(self, name, val)
        except AttributeError:
            pass
        try:
            v = self._schema[name]
        except KeyError:
            raise AttributeError(name)
        return v.set(val)
