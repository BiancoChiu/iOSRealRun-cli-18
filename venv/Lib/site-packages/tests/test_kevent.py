import pytest

from pykdebugparser.kevent import from_kd_buf, Kevent


@pytest.mark.parametrize('raw, parsed', [
    (
            (b'\x8b\xf3\x8f1\x13\xeb\x03\x00ework_BusinessChat-7.0.1-py2.py3\xdeJ\x88\x00\x00\x00\x00\x00\x90\x00\x01'
             b'\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
            Kevent(timestamp=0x3eb13318ff38b, data=b'ework_BusinessChat-7.0.1-py2.py3',
                   values=(0x75425f6b726f7765, 0x68437373656e6973, 0x312e302e372d7461, 0x3379702e3279702d),
                   tid=8932062, debugid=50397328, eventid=50397328, func_qualifier=0)
    ),
    (
            b'\x00' * 64,
            Kevent(timestamp=0, data=b'\x00' * 32, values=(0, 0, 0, 0), tid=0, debugid=0, eventid=0, func_qualifier=0)
    ),
    (
            b'\xff' * 64,
            Kevent(timestamp=0xffffffffffffffff, data=b'\xff' * 32,
                   values=(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff),
                   tid=0xffffffffffffffff, debugid=0xffffffff, eventid=0xfffffffc, func_qualifier=0x00000003)
    )
])
def test_from_kd_buf(raw, parsed):
    assert from_kd_buf(raw) == parsed
