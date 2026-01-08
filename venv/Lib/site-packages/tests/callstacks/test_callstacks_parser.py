from uuid import UUID

from pykdebugparser.callstacks_parser import Frame
from pykdebugparser.kevent import Kevent


def test_parsing_perf_event(traces_parser, callstacks_parser):
    events = [
        Kevent(timestamp=7006023115068,
               data=(b'\t\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9, 32, 0, 0), tid=1957, debugid=620756993, eventid=620756992, func_qualifier=1),
        Kevent(timestamp=7006023115085,
               data=(b'E\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(69, 5, 0, 0), tid=1957, debugid=620888088, eventid=620888088, func_qualifier=0),
        Kevent(timestamp=7006023115105,
               data=(b'\xf0[\xc0\xb5\x01\x00\x00\x00\xd4\xe4v\x93\x01\x00\x00\x000\x99\\\x02\x01\x00'
                     b'\x00\x00<\x0b\x16\xd1\x01\x00\x00\x00'),
               values=(7344249840, 6769009876, 4334590256, 7802850108), tid=1957, debugid=620888080, eventid=620888080,
               func_qualifier=0),
        Kevent(timestamp=7006023115123,
               data=(b'\xd4\xe6v\x93\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(6769010388, 0, 0, 0), tid=1957, debugid=620888080, eventid=620888080, func_qualifier=0),
        Kevent(timestamp=7006023115140,
               data=(b'\x95\x00\x00\x00\x00\x00\x00\x00\xa5\x07\x00\x00\x00\x00\x00\x00\x80\xb1\x94m\x01'
                     b'\x00\x00\x00\x03\x00\xfc\xff\x00\x00\x00\x00'),
               values=(149, 1957, 6133428608, 4294705155), tid=1957, debugid=620822532, eventid=620822532,
               func_qualifier=0),
        Kevent(timestamp=7006023115153,
               data=(b'\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9, 0, 0, 0), tid=1957, debugid=620756994, eventid=620756992, func_qualifier=2)
    ]
    ret = list(callstacks_parser.feed_generator(traces_parser.feed_generator(events)))
    assert ret[0].timestamp == 7006023115068
    assert ret[0].tid == 1957
    assert ret[0].frames == [
        Frame(0x1b5c05bf0, None, None),
        Frame(0x19376e4d4, None, None),
        Frame(0x1025c9930, None, None),
        Frame(0x1d1160b3c, None, None),
        Frame(0x19376e6d4, None, None),
    ]


def test_parsing_with_images(traces_parser, callstacks_parser):
    events = [
        Kevent(timestamp=2087564153638,
               data=(b'\x19\xdd*\xd4E\xe01\x97\xa5\xc4S\xb3W\xf3a\xa0\x000u\xaa\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(10894735564102884633, 11556785676805719205, 0x1aa753000, 0), tid=200651, debugid=520421376,
               eventid=520421376, func_qualifier=0),
        Kevent(timestamp=7006023115068,
               data=(b'\t\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9, 32, 0, 0), tid=1957, debugid=620756993, eventid=620756992, func_qualifier=1),
        Kevent(timestamp=7006023115085,
               data=(b'E\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(69, 5, 0, 0), tid=1957, debugid=620888088, eventid=620888088, func_qualifier=0),
        Kevent(timestamp=7006023115105,
               data=(b'\xf0[\xc0\xb5\x01\x00\x00\x00\xd4\xe4v\x93\x01\x00\x00\x000\x99\\\x02\x01\x00'
                     b'\x00\x00<\x0b\x16\xd1\x01\x00\x00\x00'),
               values=(7344249840, 6769009876, 4334590256, 7802850108), tid=1957, debugid=620888080, eventid=620888080,
               func_qualifier=0),
        Kevent(timestamp=7006023115123,
               data=(b'\xd4\xe6v\x93\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(6769010388, 0, 0, 0), tid=1957, debugid=620888080, eventid=620888080, func_qualifier=0),
        Kevent(timestamp=7006023115140,
               data=(b'\x95\x00\x00\x00\x00\x00\x00\x00\xa5\x07\x00\x00\x00\x00\x00\x00\x80\xb1\x94m\x01'
                     b'\x00\x00\x00\x03\x00\xfc\xff\x00\x00\x00\x00'),
               values=(149, 1957, 6133428608, 4294705155), tid=1957, debugid=620822532, eventid=620822532,
               func_qualifier=0),
        Kevent(timestamp=7006023115153,
               data=(b'\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9, 0, 0, 0), tid=1957, debugid=620756994, eventid=620756992, func_qualifier=2)
    ]
    ret = list(callstacks_parser.feed_generator(traces_parser.feed_generator(events)))
    assert ret[0].timestamp == 7006023115068
    assert ret[0].tid == 1957
    assert ret[0].frames == [
        Frame(0x1b5c05bf0, UUID('19dd2ad4-45e0-3197-a5c4-53b357f361a0'), 0xb4b2bf0),
        Frame(0x19376e4d4, None, None),
        Frame(0x1025c9930, None, None),
        Frame(0x1d1160b3c, UUID('19dd2ad4-45e0-3197-a5c4-53b357f361a0'), 0x26a0db3c),
        Frame(0x19376e6d4, None, None),
    ]
