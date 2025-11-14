from pykdebugparser.kevent import Kevent


def test_read(traces_parser):
    events = [
        Kevent(timestamp=15783429453,
               data=(b'\x07\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xf1\x1b\x01\x00\x00\x00\xd6c'
                     b'\x00\x00\x00\x00\x00\x00h\xd8:m\x01\x00\x00\x00'),
               values=(7, 4763795456, 25558, 6127540328), tid=7573, debugid=67895309, eventid=67895308,
               func_qualifier=1),
        Kevent(timestamp=15783456070,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\xd6c\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 25558, 0, 144), tid=7573, debugid=67895310, eventid=67895308, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'read(7, 0x11bf1c000, 25558), count: 25558'


def test_csops_audittoken_16(traces_parser):
    events = [
        Kevent(timestamp=1805610285184,
               data=(b'C\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xa0&\xa1m'
                     b'\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'),
               values=(67, 16, 6134245024, 8), tid=1599, debugid=67895977, eventid=67895976, func_qualifier=1),
        Kevent(timestamp=1805610285735,
               data=(b'"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x00\x00\x00'),
               values=(34, 0, 0, 67), tid=1599, debugid=67895978, eventid=67895976, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'csops_audittoken(67, CS_OPS_16, 0x16da126a0, 8), errno: ERANGE(34)'
