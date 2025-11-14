from io import BytesIO

from pykdebugparser.kd_buf_parser import RAW_VERSION2_BYTES
from pykdebugparser.kevent import Kevent
from pykdebugparser.pykdebugparser import PyKdebugParser


def test_kevents():
    events_buf = RAW_VERSION2_BYTES + b'\x00' * 0x11c
    events_buf += (b'\xa50\x147_\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                   b'\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00y\xd8\t\x00\x00\x00\x00'
                   b'\x00*\x03\x0c\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    parser = PyKdebugParser()
    events = list(parser.kevents(BytesIO(events_buf)))
    assert events == [
        Kevent(timestamp=7006015729829,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 454), tid=645241, debugid=67896106, eventid=67896104, func_qualifier=2)
    ]


def test_kevents_filter_tid():
    events_buf = RAW_VERSION2_BYTES + b'\x00' * 0x11c
    events_buf += (b'\xa50\x147_\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                   b'\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00y\xd8\t\x00\x00\x00\x00'
                   b'\x00*\x03\x0c\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    parser = PyKdebugParser()
    parser.filter_tid = 645241
    events = list(parser.kevents(BytesIO(events_buf)))
    assert events == [
        Kevent(timestamp=7006015729829,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 454), tid=645241, debugid=67896106, eventid=67896104, func_qualifier=2)
    ]
    parser.filter_tid = 3
    events = list(parser.kevents(BytesIO(events_buf)))
    assert events == []
