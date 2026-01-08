from pykdebugparser.kevent import Kevent
from pykdebugparser.trace_handlers.perf import CallstackFlag, KperfTiState, SamplerAction


def test_perf_event(traces_parser):
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
    ret = list(traces_parser.feed_generator(events))[4]
    assert ret.sample_what == [SamplerAction.SAMPLER_TH_INFO, SamplerAction.SAMPLER_USTACK]
    assert ret.actionid == 32
    assert ret.th_info.pid == 149
    assert ret.th_info.tid == 1957
    assert ret.th_info.dq_addr == 0x16d94b180
    assert ret.th_info.runmode == [KperfTiState.KPERF_TI_RUNNING, KperfTiState.KPERF_TI_RUNNABLE]
    assert ret.cs_flags == [CallstackFlag.CALLSTACK_VALID, CallstackFlag.CALLSTACK_64BIT,
                            CallstackFlag.CALLSTACK_KERNEL_WORDS]
    assert ret.cs_frames == [0x1b5c05bf0, 0x19376e4d4, 0x1025c9930, 0x1d1160b3c, 0x19376e6d4]


def test_perf_event_without_stack(traces_parser):
    events = [
        Kevent(timestamp=7006023115068,
               data=(b'\t\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9, 32, 0, 0), tid=1957, debugid=620756993, eventid=620756992, func_qualifier=1),
        Kevent(timestamp=7006023115153,
               data=(b'\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9, 0, 0, 0), tid=1957, debugid=620756994, eventid=620756992, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].sample_what == [SamplerAction.SAMPLER_TH_INFO, SamplerAction.SAMPLER_USTACK]
    assert ret[0].actionid == 32
    assert ret[0].th_info is None
    assert ret[0].cs_flags is None
    assert ret[0].cs_frames is None


def test_thd_data(traces_parser):
    events = [
        Kevent(timestamp=15773877915,
               data=(b'P\x00\x00\x00\x00\x00\x00\x00\x9d\x04\x00\x00\x00\x00\x00\x00\x00'
                     b'\xfa\x17\x05\x01\x00\x00\x00\x03\x00\xfc\xff\x00\x00\x00\x00'),
               values=(80, 1181, 4380424704, 4294705155), tid=1181, debugid=620822532, eventid=620822532,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    thd_data = ret[0]
    assert thd_data.pid == 80
    assert thd_data.tid == 1181
    assert thd_data.dq_addr == 0x10517fa00
    assert thd_data.runmode == [KperfTiState.KPERF_TI_RUNNING, KperfTiState.KPERF_TI_RUNNABLE]


def test_thd_cswitch(traces_parser):
    events = [
        Kevent(timestamp=15779569737,
               data=(b'`\x10\x00\x00\x00\x00\x00\x00P\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(4192, 80, 0, 0), tid=4192, debugid=620822548, eventid=620822548, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    thd_cswitch = ret[0]
    assert thd_cswitch.tid == 4192
    assert thd_cswitch.pid == 80


def test_stk_udata(traces_parser):
    events = [
        Kevent(timestamp=15771902115,
               data=(b'\x94\xec\x12\x93\x01\x00\x00\x00\xa8\xf8\x12\x93\x01\x00\x00\x008\x93'
                     b'\x13\x93\x01\x00\x00\x00\xa4\xa5\xbe\xd9\x01\x00\x00\x00'),
               values=(6762458260, 6762461352, 6762500920, 7948117412), tid=7565, debugid=620888080, eventid=620888080,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    stk_udata = ret[0]
    assert stk_udata.frames == [0x19312ec94, 0x19312f8a8, 0x193139338, 0x1d9bea5a4]


def test_stk_uhdr(traces_parser):
    events = [
        Kevent(timestamp=15772304192,
               data=(b'E\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(69, 7, 0, 0), tid=6206, debugid=620888088, eventid=620888088, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    stk_uhdr = ret[0]
    assert stk_uhdr.flags == [CallstackFlag.CALLSTACK_VALID, CallstackFlag.CALLSTACK_64BIT,
                              CallstackFlag.CALLSTACK_KERNEL_WORDS]
    assert stk_uhdr.nframes == 7
