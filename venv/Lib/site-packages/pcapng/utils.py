import socket
import struct


def pack_ipv4(data):
    return socket.inet_aton(data)


def unpack_ipv4(data):
    return socket.inet_ntoa(data)


def _get_pairs(data):
    """Return data in pairs

    This uses a clever hack, based on the fact that zip will consume
    items from the same iterator, for each reference found in each
    row.

    Example::

        >>> _get_pairs([1, 2, 3, 4])
        [(1, 2), (3, 4)]

    """
    return list(zip(*((iter(data),) * 2)))


def pack_ipv6(data):
    return socket.inet_pton(socket.AF_INET6, data)


def unpack_ipv6(data):
    return socket.inet_ntop(socket.AF_INET6, data)


def pack_macaddr(data):
    a = [int(x, 16) for x in data.split(":")]
    return struct.pack("!6B", *a)


def unpack_macaddr(data):
    return ":".join(format(x, "02x") for x in data)


def pack_euiaddr(data):
    a = [int(x, 16) for x in data.split(":")]
    return struct.pack("!8B", *a)


def unpack_euiaddr(data):
    return unpack_macaddr(data)


def unpack_timestamp_resolution(data):
    """
    Unpack a timestamp resolution.

    Returns a floating point number representing the timestamp
    resolution (multiplier).
    """
    if len(data) != 1:
        raise ValueError("Data must be exactly one byte")
    num = data[0]
    base = 2 if (num >> 7 & 1) else 10
    exponent = num & 0b01111111
    return base ** (-exponent)


def pack_timestamp_resolution(base, exponent):
    """
    Pack a timestamp resolution.

    :param base: 2 or 10
    :param exponent: negative power of the base to be encoded
    """
    exponent = abs(exponent)
    if base == 2:
        return struct.pack("B", exponent | 0b10000000)
    if base == 10:
        return struct.pack("B", exponent)
    raise ValueError("Supported bases are: 2, 10")
