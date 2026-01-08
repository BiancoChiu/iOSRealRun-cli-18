"""
Module providing facilities for handling struct-like data.
"""

import abc
import struct
import warnings
from collections import defaultdict
from collections.abc import Iterable, Mapping

from pcapng import strictness as strictness
from pcapng._compat import namedtuple
from pcapng.exceptions import (
    BadMagic,
    CorruptedFile,
    PcapngLoadError,
    StreamEmpty,
    TruncatedFile,
)
from pcapng.flags import FlagBool, FlagEnum, FlagField, FlagUInt, FlagWord
from pcapng.utils import (
    pack_euiaddr,
    pack_ipv4,
    pack_ipv6,
    pack_macaddr,
    unpack_euiaddr,
    unpack_ipv4,
    unpack_ipv6,
    unpack_macaddr,
)

SECTION_HEADER_MAGIC = 0x0A0D0D0A
BYTE_ORDER_MAGIC = 0x1A2B3C4D
BYTE_ORDER_MAGIC_INVERSE = 0x4D3C2B1A

# Anything greater and we cannot safely read
# todo: add support for this!
CURRENT_SUPPORTED_VERSION = (1, 0)


INT_FORMATS = {8: "b", 16: "h", 32: "i", 64: "q"}

# Type name constants, to keep a list and prevent typos
TYPE_BYTES = "bytes"
TYPE_STRING = "string"
TYPE_IPV4 = "ipv4"
TYPE_IPV4_MASK = "ipv4+mask"
TYPE_IPV6 = "ipv6"
TYPE_IPV6_PREFIX = "ipv6+prefix"
TYPE_MACADDR = "macaddr"
TYPE_EUIADDR = "euiaddr"
TYPE_TYPE_BYTES = "type+bytes"
TYPE_EPBFLAGS = "epb_flags"
TYPE_OPT_CUSTOM_STR = "opt_custom_str"
TYPE_OPT_CUSTOM_BYTES = "opt_custom_bytes"

TYPE_U8 = "u8"  # Unsigned integer, 8 bits
TYPE_U16 = "u16"
TYPE_U32 = "u32"
TYPE_U64 = "u64"
TYPE_I8 = "i8"  # Signed integer, 8 bits
TYPE_I16 = "i16"
TYPE_I32 = "i32"
TYPE_I64 = "i64"

_numeric_types = {
    TYPE_U8: "B",
    TYPE_I8: "b",
    TYPE_U16: "H",
    TYPE_I16: "h",
    TYPE_U32: "I",
    TYPE_I32: "i",
    TYPE_U64: "Q",
    TYPE_I64: "q",
}

NRB_RECORD_END = 0
NRB_RECORD_IPv4 = 1
NRB_RECORD_IPv6 = 2


def read_int(stream, size, signed=False, endianness="="):
    """
    Read (and decode) an integer number from a binary stream.

    :param stream: an object providing a ``read()`` method
    :param size: the size, in bits, of the number to be read.
        Supported sizes are: 8, 16, 32 and 64 bits.
    :param signed: Whether a signed or unsigned number is required.
        Defaults to ``False`` (unsigned int).
    :param endianness: specify the endianness to use to decode the number,
        in the same format used by Python :py:mod:`struct` module.
        Defaults to '=' (native endianness). '!' means "network" endianness
        (big endian), '<' little endian, '>' big endian.
    :return: the read integer number
    """
    fmt = INT_FORMATS.get(size)
    fmt = fmt.lower() if signed else fmt.upper()
    assert endianness in "<>!="
    fmt = endianness + fmt
    size_bytes = size // 8
    data = read_bytes(stream, size_bytes)
    return struct.unpack(fmt, data)[0]


def write_int(number, stream, size, signed=False, endianness="="):
    """
    Write (and encode) an integer number to a binary stream.

    :param number: the integer number to write
    :param stream: an object providing a ``write()`` method
    :param size: the size, in bits, of the number to be written.
        Supported sizes are: 8, 16, 32 and 64 bits.
    :param signed: Whether a signed or unsigned number is required.
        Defaults to ``False`` (unsigned int).
    :param endianness: specify the endianness to use to encode the number,
        in the same format used by Python :py:mod:`struct` module.
        Defaults to '=' (native endianness). '!' means "network" endianness
        (big endian), '<' little endian, '>' big endian.

    """
    fmt = INT_FORMATS.get(size)
    fmt = fmt.lower() if signed else fmt.upper()
    assert endianness in "<>!="
    fmt = endianness + fmt
    write_bytes(stream, struct.pack(fmt, number))


def read_section_header(stream):
    """
    Read a section header block from a stream.

    .. note::
        The byte order magic will be removed from the returned data
        This is ok as we don't need it anymore once we determined
        the correct endianness of the section.

    :returns: a dict containing the ``'endianness'`` and ``'data'`` keys
        that will be used to construct a :py:mod:`~pcapng.blocks.SectionHeader`
        instance.
    """

    # Read the length as raw bytes, then keep for later (since we
    # don't know the section endianness yet, we cannot parse this)
    blk_len_raw = read_bytes(stream, 4)

    # Read the "byte order magic" and see which endianness reports
    # it correctly (should be 0x1a2b3c4d)
    byte_order_magic = read_int(stream, 32, False, ">")  # Default BIG
    if byte_order_magic == BYTE_ORDER_MAGIC:
        endianness = ">"  # BIG
    else:
        if byte_order_magic != BYTE_ORDER_MAGIC_INVERSE:
            # We got an invalid number..
            raise BadMagic(
                "Wrong byte order magic: got 0x{0:08X}, expected "
                "0x{1:08X} or 0x{2:08X}".format(
                    byte_order_magic, BYTE_ORDER_MAGIC, BYTE_ORDER_MAGIC_INVERSE
                )
            )
        endianness = "<"  # LITTLE

    # Now we can safely decode the block length from the bytes we read earlier
    blk_len = struct.unpack(endianness + "I", blk_len_raw)[0]

    # ..and we then just want to read the appropriate amount of raw data.
    # Exclude: magic, len, bom, len (16 bytes)
    payload_size = blk_len - (4 + 4 + 4 + 4)
    block_data = read_bytes_padded(stream, payload_size)

    # Double-check lenght at block end
    blk_len2 = read_int(stream, 32, False, endianness)
    if blk_len != blk_len2:
        raise CorruptedFile(
            "Mismatching block lengths: {0} and {1}".format(blk_len, blk_len2)
        )

    return {
        "endianness": endianness,
        "data": block_data,
    }


def read_block_data(stream, endianness):
    """
    Read block data from a stream.

    Each "block" is in the form:

    - 32bit integer indicating the size (including header and size)
    - block payload (the above-specified number of bytes minus 12)
    - 32bit integer indicating the size (again)

    :param stream: the stream from which to read data
    :param endianness: Endianness marker, one of '<', '>', '!', '='.
    """

    block_length = read_int(stream, 32, signed=False, endianness=endianness)
    payload_length = block_length - 12  # bytes
    block_data = read_bytes_padded(stream, payload_length)
    block_length2 = read_int(stream, 32, signed=False, endianness=endianness)
    if block_length != block_length2:
        raise CorruptedFile(
            "Mismatching block lengths: {0} and {1}".format(block_length, block_length2)
        )
    return block_data


def read_bytes(stream, size):
    """
    Read the given amount of raw bytes from a stream.

    :param stream: the stream from which to read data
    :param size: the size to read, in bytes
    :returns: the read data
    :raises: :py:exc:`~pcapng.exceptions.StreamEmpty` if zero bytes were read
    :raises: :py:exc:`~pcapng.exceptions.TruncatedFile` if 0 < bytes < size
        were read
    """

    if size == 0:
        return b""

    data = stream.read(size)
    if len(data) == 0:
        raise StreamEmpty("Zero bytes read from stream")
    if len(data) < size:
        raise TruncatedFile(
            "Trying to read {0} bytes, only got {1}".format(size, len(data))
        )
    return data


def write_bytes(stream, data):
    """
    Write the given amount of raw bytes to a stream.

    :param stream: the stream into which to write data
    :param data: the data to write
    """
    stream.write(data)


def read_bytes_padded(stream, size, pad_block_size=4):
    """
    Read the given amount of bytes from a stream, plus read and discard
    any necessary extra byte to align up to the pad_block_size-sized
    next block.

    :param stream: the stream from which to read data
    :param size: the size to read, in bytes
    :returns: the read data
    :raises: :py:exc:`~pcapng.exceptions.StreamEmpty` if zero bytes were read
    :raises: :py:exc:`~pcapng.exceptions.TruncatedFile` if 0 < bytes < size
        were read
    """

    if stream.tell() % pad_block_size != 0:
        raise RuntimeError("Stream is misaligned!")

    data = read_bytes(stream, size)
    padding = (pad_block_size - (size % pad_block_size)) % pad_block_size
    if padding > 0:
        read_bytes(stream, padding)
    return data


def write_bytes_padded(stream, data, pad_block_size=4):
    """
    Read the given amount of bytes from a stream, plus read and discard
    any necessary extra byte to align up to the pad_block_size-sized
    next block.

    :param stream: the stream from which to read data
    :param size: the size to read, in bytes
    :returns: the read data
    :raises: :py:exc:`~pcapng.exceptions.StreamEmpty` if zero bytes were read
    :raises: :py:exc:`~pcapng.exceptions.TruncatedFile` if 0 < bytes < size
        were read
    """

    write_bytes(stream, data)
    padding = (pad_block_size - (len(data) % pad_block_size)) % pad_block_size
    if padding > 0:
        write_bytes(stream, bytes([0] * padding))


class StructField(object):
    """Abstract base class for struct fields"""

    __metaclass__ = abc.ABCMeta
    __slots__ = []

    @abc.abstractmethod
    def load(self, stream, endianness, seen=None):
        pass

    def __repr__(self):
        return "{0}()".format(self.__class__.__name__)

    def __unicode__(self):
        return self.__repr__().encode("UTF-8")

    def encode_finish(self, stream, endianness):
        pass


class RawBytes(StructField):
    """
    Field containing a fixed-width amount of raw bytes

    :param size: field size, in bytes
    """

    __slots__ = ["size"]

    def __init__(self, size):
        self.size = size  # in bytes!

    def load(self, stream, endianness=None, seen=None):
        return read_bytes_padded(stream, self.size)

    def encode(self, value, stream, endianness=None):
        write_bytes_padded(stream, value)

    def __repr__(self):
        return "{0}(size={1!r})".format(self.__class__.__name__, self.size)


class IntField(StructField):
    """
    Field containing an integer number.

    :param size: number size, in bits. Currently supported
        are 8, 16, 32 and 64-bit integers
    :param signed: whether the number is a signed or unsigned
        integer. Defaults to False (unsigned)
    """

    __slots__ = ["size", "signed"]

    def __init__(self, size, signed=False):
        self.size = size  # in bits!
        self.signed = signed

    def load(self, stream, endianness, seen=None):
        number = read_int(stream, self.size, signed=self.signed, endianness=endianness)
        return number

    def encode(self, number, stream, endianness):
        if not isinstance(number, int):
            raise TypeError("'{}' is not numeric".format(number))
        write_int(number, stream, self.size, signed=self.signed, endianness=endianness)

    def __repr__(self):
        return "{0}(size={1!r}, signed={2!r})".format(
            self.__class__.__name__, self.size, self.signed
        )


class OptionsField(StructField):
    """
    Field containing some options.

    :param options_schema:
        Same as the ``schema`` parameter to :py:class:`Options` class
        constructor.
    """

    __slots__ = ["options_schema"]

    def __init__(self, options_schema):
        self.options_schema = options_schema

    def load(self, stream, endianness, seen=None):
        options = read_options(stream, endianness)
        return Options(schema=self.options_schema, data=options, endianness=endianness)

    def encode(self, options, stream, endianness):
        write_options(stream, options)

    def __repr__(self):
        return "{0}({1!r})".format(self.__class__.__name__, self.options_schema)


class PacketBytes(StructField):
    """
    Field containing some "packet data", used in the Packet
    and EnhancedPacket blocks.

    The packet data is composed of three fields (returned in a tuple):

    - captured len (uint32)
    - packet len (uint32)
    - packet data (captured_len-sized binary data)
    """

    __slots__ = ["dependency"]

    def __init__(self, len_field):
        self.dependency = len_field

    def load(self, stream, endianness, seen=[]):
        try:
            length = seen[self.dependency]
        except TypeError:
            raise PcapngLoadError(
                "PacketBytes dependent on field '{0}' which wasn't passed".format(
                    self.dependency
                )
            )
        except KeyError:
            raise PcapngLoadError(
                "PacketBytes dependent on field '{0}' which was never found".format(
                    self.dependency
                )
            )
        return read_bytes_padded(stream, length)

    def encode(self, packet, stream, endianness=None):
        if not packet:
            raise ValueError("Packet invalid")
        write_bytes_padded(stream, packet)


class ListField(StructField):
    """
    A list field is a variable amount of fields of some other type.
    Used for packets containing multiple "items", such as
    :py:class:`~pcapng.blocks.NameResolution`.

    It will keep loading data using a subfield until a
    :py:exc:`~pcapng.exceptions.StreamEmpty` excaption is raised, indicating
    we reached the end of data (note that a sub-field might even "simulate"
    a stream end once it reaches some end marker in the file).

    Values are returned in a list.

    :param subfield: a :py:class:`StructField` sub-class instance to be
        used to read values from the stream.
    """

    __slots__ = ["subfield"]

    def __init__(self, subfield):
        self.subfield = subfield

    def load(self, stream, endianness, seen=None):
        return list(self._iter_load(stream, endianness))

    def _iter_load(self, stream, endianness):
        while True:
            try:
                yield self.subfield.load(stream, endianness)
            except StreamEmpty:
                return

    def encode(self, list_data, stream, endianness):
        for rec in list_data:
            self.subfield.encode(rec, stream, endianness)
        self.subfield.encode_finish(stream, endianness)

    def __repr__(self):
        return "{0}({1!r})".format(self.__class__.__name__, self.subfield)


class NameResolutionRecordField(StructField):
    """
    A name resolution record field contains an item of data used in
    the :py:class:`~pcapng.blocks.NameResolution` block.

    it is composed of three fields:

    - record type (uint16)
    - record length (uint16)
    - payload

    Accepted types are:

    - ``0x00`` - end marker
    - ``0x01`` - ipv4 address resolution
    - ``0x02`` - ipv6 address resolution

    In both cases, the payload is composed of a valid address in the
    selected IP version, followed by null-separated/terminated domain names.
    """

    __slots__ = []

    def load(self, stream, endianness, seen=None):
        record_type = read_int(stream, 16, False, endianness)
        record_length = read_int(stream, 16, False, endianness)

        if record_type == NRB_RECORD_END:
            raise StreamEmpty("End marker reached")

        data = read_bytes_padded(stream, record_length)

        if record_type == NRB_RECORD_IPv4:
            return {
                "type": record_type,
                "address": unpack_ipv4(data[:4]),
                "names": [x.decode() for x in data[4:].split(b"\x00") if x != b""],
            }

        if record_type == NRB_RECORD_IPv6:
            return {
                "type": record_type,
                "address": unpack_ipv6(data[:16]),
                "names": [x.decode() for x in data[16:].split(b"\x00") if x != b""],
            }

        return {"type": record_type, "raw": data}

    def encode(self, d, stream, endianness):
        if d["type"] == NRB_RECORD_END:
            # Don't let the user add records of this type.
            # We take care of it in `encode_finish()` below
            return

        write_int(d["type"], stream, 16, endianness=endianness)
        if d["type"] == NRB_RECORD_IPv4:
            raw = pack_ipv4(d["address"])
            raw += (b"\x00".join([s.encode() for s in d["names"]])) + b"\x00"
            write_int(len(raw), stream, 16, endianness=endianness)
            write_bytes_padded(stream, raw)
        elif d["type"] == NRB_RECORD_IPv6:
            raw = pack_ipv6(d["address"])
            raw += (b"\x00".join([s.encode() for s in d["names"]])) + b"\x00"
            write_int(len(raw), stream, 16, endianness=endianness)
            write_bytes_padded(stream, raw)
        else:
            write_int(len(d["raw"]), stream, 16, endianness=endianness)
            write_bytes_padded(stream, d["raw"])

    def encode_finish(self, stream, endianness):
        write_int(NRB_RECORD_END, stream, 16, endianness=endianness)
        write_int(0, stream, 16, endianness=endianness)


def read_options(stream, endianness):
    """
    Read "options" from an "options block" in a stream, until a
    ``StreamEmpty`` exception is caught, or an end marker is reached.

    Each option is composed by:

    - option_code (uint16)
    - value_length (uint16)
    - value (value_length-sized binary data)

    The end marker is simply an option with code ``0x0000`` and no payload
    """

    def _iter_read_options(stream, endianness):
        while True:
            try:
                option_code = read_int(stream, 16, False, endianness)
                option_length = read_int(stream, 16, False, endianness)

                if option_code == 0:  # End of options
                    return

                payload = read_bytes_padded(stream, option_length)
                yield option_code, payload

            except StreamEmpty:
                return

    return list(_iter_read_options(stream, endianness))


def write_options(stream, options):
    """
    Each option is composed by:

    - option_code (uint16)
    - value_length (uint16)
    - value (value_length-sized binary data)

    The end marker is simply an option with code ``0x0000``, length 0,
    and no payload
    """

    if not options:
        # Options are optional; if there are none we don't need opt_endofopt
        return

    for key in options:
        code = options._field_names[key]
        values = options.get_all_raw(key)
        if len(values) > 1 and not options.schema[code].multiple:
            strictness.problem(
                "writing repeated option {} '{}' not permitted by pcapng spec".format(
                    code, options._get_name_alias(code)
                )
            )
            if strictness.should_fix():
                values = values[:1]
        for value in values:
            write_int(code, stream, 16, False, options.endianness)
            write_int(len(value), stream, 16, False, options.endianness)
            write_bytes_padded(stream, value)
    # Write the end marker
    write_int(0, stream, 32, False, options.endianness)


class EPBFlags(FlagWord):
    """Class representing the epb_flags option on an EPB"""

    __slots__ = []

    def __init__(self, val=0):
        super(EPBFlags, self).__init__(
            [
                FlagField("inout", FlagEnum, 2, ("NA", "inbound", "outbound")),
                FlagField(
                    "casttype",
                    FlagEnum,
                    3,
                    ("NA", "unicast", "multicast", "broadcast", "promiscuous"),
                ),
                FlagField("fcslen", FlagUInt, 4),
                FlagField("reserved", FlagUInt, 7),
                FlagField("err_16", FlagBool),
                FlagField("err_17", FlagBool),
                FlagField("err_18", FlagBool),
                FlagField("err_19", FlagBool),
                FlagField("err_20", FlagBool),
                FlagField("err_21", FlagBool),
                FlagField("err_22", FlagBool),
                FlagField("err_23", FlagBool),
                FlagField("err_crc", FlagBool),
                FlagField("err_long", FlagBool),
                FlagField("err_short", FlagBool),
                FlagField("err_frame_gap", FlagBool),
                FlagField("err_frame_align", FlagBool),
                FlagField("err_frame_delim", FlagBool),
                FlagField("err_preamble", FlagBool),
                FlagField("err_symbol", FlagBool),
            ],
            nbits=32,
            initial=val,
        )


# Class representing a single option schema for Options.
# require code and name; by default, empty ftype, forbid multiples
Option = namedtuple(
    "Option", ("code", "name", "ftype", "multiple"), defaults=(None, False)
)


class Options(Mapping):
    """
    Wrapper object used to easily access the contents of an "options"
    field.

    Fields can be accessed either by numerical id or by name (if one was
    specified in the schema).

    .. note::

        When iterating the object (or calling :py:meth:`keys` /
        :py:meth:`iterkeys` / :py:meth:`viewkeys`) string keys will be
        returned if possible in place of numeric keys.  (The purpose of this
        is to achieve better readability, for example, when converting
        to a dictionary).

    :param schema:
        Definition of the known options: a list of Option objects.

        The following value types are currently supported:

        - ``string``: convert value to a unicode string, using utf-8 encoding
        - ``{u,i}{8,16,32,64}``: (un)signed integer of the specified length
        - ``ipv4``: a single ipv4 address [4 bytes]
        - ``ipv4+mask``: an ipv4 address followed by a netmask [8 bytes]
        - ``ipv6``: a single ipv6 address [16 bytes]
        - ``ipv6+prefix``: an ipv6 address followed by prefix length [17 bytes]
        - ``macaddr``: a mac address [6 bytes]
        - ``euiaddr``: a eui address [8 bytes]
        - ``epb_flags``: 32-bit bitmask as per pcapng spec section 4.3.1
        - ``type+bytes``: field where the first byte is a type, and
          the remainder is bytes
        - ``opt_custom_str`` and ``opt_custom_bytes``: 4 bytes of Private
          Enterprise Number, followed by str or bytes (see pcapng spec,
          section 3.5.1)

    :param data:
        Initial data for the options. A dict of ``code: value`` items.
        Items with the same code may be repeated; only the first one will be
        accessible using subscript ``options[code]``; the others can be
        accessed using :py:meth:`get_all` and related methods

    :param endianness:
        The current endianness of the section these options came from.
        Required in order to load numeric fields.
    """

    __slots__ = [
        "schema",
        "_field_names",
        "data",
        "endianness",
    ]

    def __init__(self, schema, data, endianness):
        self.schema = {}  # Schema of option fields: {<code>: Option(...)}
        self._field_names = {}  # Map names to codes
        self.data = defaultdict(list)  # option data, with numeric option IDs as keys
        self.endianness = endianness  # one of '<>!='

        # This is the default schema, common to all objects
        for item in [
            Option(0, "opt_endofopt"),
            Option(1, "opt_comment", TYPE_STRING, multiple=True),
            # The spec calls all these next options ``opt_custom`` --
            # I've renamed them here so they can be told apart
            Option(2988, "custom_str_safe", TYPE_OPT_CUSTOM_STR, multiple=True),
            Option(2989, "custom_bytes_safe", TYPE_OPT_CUSTOM_BYTES, multiple=True),
            Option(19372, "custom_str", TYPE_OPT_CUSTOM_STR, multiple=True),
            Option(19373, "custom_bytes", TYPE_OPT_CUSTOM_BYTES, multiple=True),
        ] + list(schema):
            if not isinstance(item, Option):
                raise TypeError("expected option, got '{}'".format(item))
            self.schema[item.code] = item
        self._field_names = {x.name: x.code for x in self.schema.values()}

        # Update raw data with current values
        self._update_data(data)

    # -------------------- Nice interface :) --------------------

    def __eq__(self, other):
        return self.data == other.data

    def __getitem__(self, name):
        code = self._resolve_name(name)
        if code not in self.data:
            # The defaultdict would create an empty entry if we just let this slide.
            # `tests/test_structs.py` expects a KeyError to be raised here instead.
            raise KeyError(name)
        return self.data[code][0]

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        for key in self.data:
            yield self._get_name_alias(key)

    def __setitem__(self, name, value):
        # This also gets called for ``block.options[name] += value``
        # as if ``block.options[name] = block.options[name] + value``
        # which means that, if value is a string, each character gets added
        # separately. Workaround: wrap the string in [ ], or use ``add()``
        code = self._resolve_name(name)
        if isinstance(value, Iterable) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            # We're being assigned a list/iterable, use its values for our list
            self.data[code] = list(value)
            self._check_multiples(code)
        else:
            # We're being assigned a single value, store as a one-item list
            self.data[code] = [value]

    def __delitem__(self, name):
        code = self._resolve_name(name)
        del self.data[code]

    def get_all(self, name):
        """Get all values for the given option"""
        code = self._resolve_name(name)
        return self.data[code]

    def get_raw(self, name):
        """Get raw value for the given option"""
        code = self._resolve_name(name)
        return self._encode_value(self.data[code][0], self.schema[code].ftype)

    def get_all_raw(self, name):
        """Get all raw values for the given option"""
        code = self._resolve_name(name)
        return [self._encode_value(x, self.schema[code].ftype) for x in self.data[code]]

    def iter_all_items(self):
        """
        Similar to :py:meth:`iteritems` but will yield a list of values
        as the second tuple field.
        """
        for key in self:
            yield key, self.get_all(key)

    def add(self, name, value):
        """Add a value to the given-named option"""
        code = self._resolve_name(name)
        self.data[code].append(value)
        self._check_multiples(code)

    def __repr__(self):
        args = dict(self.iter_all_items())
        name = self.__class__.__name__
        return "{0}({1!r})".format(name, args)

    # -------------------- Internal methods --------------------

    def _update_data(self, data):
        if data is None:
            return

        for code, value in data:
            self.data[code].append(self._decode(code, value))
            if len(self.data[code]) > 1 and not self.schema[code].multiple:
                try:
                    name = "{} '{}'".format(code, self.schema[code].name)
                except KeyError:
                    name = "{} (unknown)".format(code)
                # This code gets called when reading a file. We don't want
                # to potentially abort in this case, just warn
                strictness.warn(
                    "repeated option {} not permitted by pcapng spec".format(name)
                )

    def _check_multiples(self, code):
        """Check if a non-repeatable option is repeated"""
        if len(self.data[code]) > 1 and not self.schema[code].multiple:
            strictness.problem(
                "repeated option {} '{}' not permitted by pcapng spec".format(
                    code, self._get_name_alias(code)
                )
            )
            if strictness.should_fix():
                self.data[code] = self.data[code][:1]

    def _resolve_name(self, name):
        code = self._field_names.get(name, name)
        if code == 0:
            # opt_endofopt is special and should never be touched by the user
            raise KeyError(name)
        return code

    def _get_name_alias(self, code):
        if code in self.schema:
            return self.schema[code].name
        return code

    def _decode(self, code, value):
        code = self._resolve_name(code)
        if code in self.schema:
            return self._decode_value(value, self.schema[code].ftype)
        return value

    def _decode_all(self, code, values):
        code = self._resolve_name(code)
        if code in self.schema:
            return [
                self._decode_value(value, self.schema[code].ftype) for value in values
            ]
        return values

    def _decode_value(self, value, ftype):
        assert isinstance(value, (bytes, bytearray))

        if ftype is None:
            warnings.warn(
                DeprecationWarning(
                    'Field type should not be "None". Please explicitly '
                    "use TYPE_BYTES instead."
                )
            )
            return value

        if ftype == TYPE_BYTES:
            return value

        if hasattr(ftype, "__call__"):
            return ftype(value, self.endianness)

        if ftype == TYPE_STRING:
            return value.decode("utf-8")

        if ftype in ("str", "unicode"):
            warnings.warn(
                DeprecationWarning(
                    'The "{ftype}" field type is deprecated. Please use "string" '
                    "(TYPE_STRING) instead.".format(ftype=ftype)
                )
            )
            return value.decode("utf-8")

        if ftype in _numeric_types:
            fmt = self.endianness + _numeric_types[ftype]
            return struct.unpack(fmt, value)[0]

        if ftype == TYPE_IPV4:
            return unpack_ipv4(value)

        if ftype == TYPE_IPV4_MASK:
            return unpack_ipv4(value[:4]), unpack_ipv4(value[4:8])

        if ftype == TYPE_IPV6:
            return unpack_ipv6(value)

        if ftype == TYPE_IPV6_PREFIX:
            return (
                unpack_ipv6(value[:16]),
                struct.unpack(self.endianness + "B", value[16]),
            )

        if ftype == TYPE_MACADDR:
            return unpack_macaddr(value)

        if ftype == TYPE_EUIADDR:
            return unpack_euiaddr(value)

        if ftype == TYPE_TYPE_BYTES:
            return (value[0], value[1:])

        if ftype == TYPE_EPBFLAGS:
            fmt = self.endianness + _numeric_types[TYPE_U32]
            flg = struct.unpack(fmt, value)[0]
            return EPBFlags(flg)

        if ftype == TYPE_OPT_CUSTOM_STR:
            fmt = self.endianness + _numeric_types[TYPE_U32]
            return (struct.unpack(fmt, value[0:4])[0], value[4:].decode("utf-8"))

        if ftype == TYPE_OPT_CUSTOM_BYTES:
            fmt = self.endianness + _numeric_types[TYPE_U32]
            return (struct.unpack(fmt, value[0:4])[0], value[4:])

        raise ValueError("Unsupported field type: {0}".format(ftype))

    def _encode_value(self, value, ftype):

        if ftype is None:
            warnings.warn(
                DeprecationWarning(
                    'Field type should not be "None". Please explicitly '
                    "use TYPE_BYTES instead."
                )
            )
            assert isinstance(value, (bytes, bytearray))
            return value

        if ftype == TYPE_BYTES:
            assert isinstance(value, (bytes, bytearray))
            return value

        if hasattr(ftype, "__call__"):
            # TODO figure out how callable options work
            return ftype(value, self.endianness)

        if ftype == TYPE_STRING:
            return value.encode("utf-8")

        if ftype in ("str", "unicode"):
            warnings.warn(
                DeprecationWarning(
                    'The "{ftype}" field type is deprecated. Please use "string" '
                    "(TYPE_STRING) instead.".format(ftype=ftype)
                )
            )
            return value.encode("utf-8")

        if ftype in _numeric_types:
            fmt = self.endianness + _numeric_types[ftype]
            return struct.pack(fmt, value)

        if ftype == TYPE_IPV4:
            return pack_ipv4(value)

        if ftype == TYPE_IPV4_MASK:
            return pack_ipv4(value[0]) + pack_ipv4(value[1])

        if ftype == TYPE_IPV6:
            return pack_ipv6(value)

        if ftype == TYPE_IPV6_PREFIX:
            return pack_ipv6(value[0]) + value[1]

        if ftype == TYPE_MACADDR:
            return pack_macaddr(value)

        if ftype == TYPE_EUIADDR:
            return pack_euiaddr(value)

        if ftype == TYPE_TYPE_BYTES:
            return struct.pack("B", value[0]) + value[1]

        if ftype == TYPE_EPBFLAGS:
            fmt = self.endianness + _numeric_types[TYPE_U32]
            return struct.pack(fmt, int(value))

        if ftype == TYPE_OPT_CUSTOM_STR:
            fmt = self.endianness + _numeric_types[TYPE_U32]
            return struct.pack(fmt, value[0]) + value[1].encode("utf-8")

        if ftype == TYPE_OPT_CUSTOM_BYTES:
            fmt = self.endianness + _numeric_types[TYPE_U32]
            return struct.pack(fmt, value[0]) + value[1]

        raise ValueError("Unsupported field type: {0}".format(ftype))


def struct_decode(schema, stream, endianness="="):
    """
    Decode structured data from a stream, following a schema.

    :param schema:
        a list of three tuples: ``(name, field, default)``, where ``name`` is a
        string representing the attribute name, and ``field`` is an instance of
        a :py:class:`StructField` sub-class, providing a ``.load()`` method to
        be called on the stream to get the field value. ``default`` is used
        when manually instantiating a block, but is ignored here.

    :param stream:
        a file-like object, providing a ``.read()`` method, from which data
        will be read.

    :param endianness:
        endianness specifier, as accepted by Python struct module
        (one of ``<>!=``, defaults to ``=``).

    :return:
        a dictionary mapping the field names to decoded data
    """

    decoded = {}
    for name, field, default in schema:
        decoded[name] = field.load(stream, endianness=endianness, seen=decoded)
    return decoded


def block_decode(block, stream):
    return struct_decode(block.schema, stream, block.section.endianness)


def struct_encode(schema, obj, outstream, endianness="="):
    """
    Encode structured data to a stream.
    """
    for name, field, default in schema:
        field.encode(getattr(obj, name), outstream, endianness=endianness)
