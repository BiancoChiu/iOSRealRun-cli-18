from pykdebugparser.kevent import Kevent


def test_trace_data_thread_terminate(traces_parser):
    events = [
        Kevent(timestamp=1805581011060,
               data=(b'z\x1b\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(269178, 0, 0, 0), tid=479, debugid=117440524, eventid=117440524, func_qualifier=0)
    ]
    traces_parser.threads_pids[269178] = 61
    traces_parser.tids_names[269178] = 'terminated thread'
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'Thread terminated tid: 269178, pid: 61, name: terminated thread'


def test_trace_data_thread_terminate_missing_tid(traces_parser):
    events = [
        Kevent(timestamp=1805581011060,
               data=(b'z\x1b\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(269178, 0, 0, 0), tid=479, debugid=117440524, eventid=117440524, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'Thread terminated tid: 269178'
