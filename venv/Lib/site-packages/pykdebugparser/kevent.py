from collections import namedtuple
import enum
import struct

KDBG_EVENTID_MASK = 0xfffffffc
KDBG_FUNC_MASK = 0x00000003
KD_BUF_FORMAT = '<Q32sQIIQ'
Kevent = namedtuple('Kevent', ['timestamp', 'data', 'values', 'tid', 'debugid', 'eventid', 'func_qualifier'])


class DgbFuncQual(enum.Enum):
    """
    Event's role in the trace.
    """
    DBG_FUNC_NONE = 0
    DBG_FUNC_START = 1
    DBG_FUNC_END = 2
    DBG_FUNC_ALL = 3


def from_kd_buf(kd_buf: bytes) -> Kevent:
    """
    Create a Kevent object from a kd_buf kevent's struct.
    :param kd_buf: Buffer of kd_buf kevent's struct.
    :return: Parsed kevent.
    """
    timestamp, args_buf, tid, debugid, cpuid, unused = struct.unpack(KD_BUF_FORMAT, kd_buf)
    eventid = debugid & KDBG_EVENTID_MASK
    qual = debugid & KDBG_FUNC_MASK
    args = struct.unpack('<QQQQ', args_buf)  # There are 4 arguments, 64 bit each.
    return Kevent(timestamp, args_buf, args, tid, debugid, eventid, qual)
