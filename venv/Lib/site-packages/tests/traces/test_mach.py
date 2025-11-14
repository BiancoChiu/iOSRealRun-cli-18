from pykdebugparser.kevent import Kevent
from pykdebugparser.trace_handlers.mach import AsynchronousSystemTrapsReason, ThreadState, ProcessState, \
    DbgVmFaultType, VmProtection


def test_kernel_data_abort_same_el_exc_arm(traces_parser):
    events = [
        Kevent(timestamp=4188336568757,
               data=(b'K\x00\x00\x96\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HH\x13\x07\xf0'
                     b'\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(2516582475, 0, 18446744005108779080, 0), tid=690, debugid=16973973, eventid=16973972,
               func_qualifier=1),
        Kevent(timestamp=4188336568849,
               data=(b'K\x00\x00\x96\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HH\x13\x07\xf0'
                     b'\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(2516582475, 0, 18446744005108779080, 0), tid=690,
               debugid=16973974, eventid=16973972, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    abort = ret[0]
    assert abort.esr == 2516582475
    assert abort.far == 0
    assert abort.pc == 18446744005108779080


def test_interrupt(traces_parser):
    events = [
        Kevent(timestamp=9999124593098,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\xb0\x07p\x94\x01\x00\x00\x00\x01\x00\x00'
                     b'\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 6785337264, 1, 3), tid=825504, debugid=17104897, eventid=17104896, func_qualifier=1),
        Kevent(timestamp=9999124593219,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=825504, debugid=17104898, eventid=17104896, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    interrupt = ret[0]
    assert interrupt.pc == 0x1947007b0
    assert interrupt.is_user
    assert interrupt.type == 3


def test_user_data_abort_lower_el_exc_arm(traces_parser):
    events = [
        Kevent(timestamp=10170262586161,
               data=(b'K\x00\x00\x92\x00\x00\x00\x00\xc0bEm\x01\x00\x00\x00$]\x14\x93\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(2449473611, 6128231104, 6762552612, 0), tid=840790, debugid=16974993, eventid=16974992,
               func_qualifier=1),
        Kevent(timestamp=10170262586221,
               data=(b'K\x00\x00\x92\x00\x00\x00\x00\xc0bEm\x01\x00\x00\x00$]\x14\x93\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(2449473611, 6128231104, 6762552612, 0), tid=840790, debugid=16974994,
               eventid=16974992, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    abort = ret[0]
    assert abort.esr == 2449473611
    assert abort.far == 6128231104
    assert abort.pc == 6762552612


def test_decr_trap(traces_parser):
    events = [
        Kevent(timestamp=5453855881172,
               data=(b'\xe3\xff\xff\xff\xff\xff\xff\xff\xc4\x9dt\xac\x01\x00\x00\x00\x01\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(18446744073709551587, 7188291012, 1, 0), tid=941745, debugid=17367040, eventid=17367040,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    trace = ret[0]
    assert trace.latency == -29
    assert trace.pc == 0x1ac749dc4
    assert trace.user_mode


def test_decr_set(traces_parser):
    events = [
        Kevent(timestamp=10041923525014,
               data=(b'\xb7\xa8\x03\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(239799, 2, 0, 0), tid=267, debugid=17367044, eventid=17367044, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    decr_set = ret[0]
    assert decr_set.decr == 239799
    assert decr_set.deadline == 0
    assert decr_set.queue_count == 0


def test_msc_mach_vm_allocate_trap(traces_parser):
    events = [
        Kevent(timestamp=7476363431,
               data=(b'\x03\x02\x00\x00\x00\x00\x00\x00\x08#\xc0k\x01\x00\x00\x00\xa0o\n\x00\x00\x00'
                     b'\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'),
               values=(515, 6102721288, 683936, 1), tid=6740, debugid=17563689, eventid=17563688,
               func_qualifier=1),
        Kevent(timestamp=7476363521,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=6740, debugid=17563690, eventid=17563688,
               func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    vm_allocate_trap = ret[0]
    assert vm_allocate_trap.target == 515
    assert vm_allocate_trap.address == 0x16bc02308
    assert vm_allocate_trap.size == 0xa6fa0
    assert vm_allocate_trap.flags == 1


def test_msc_kern_mach_vm_purgable_control_trap(traces_parser):
    events = [
        Kevent(timestamp=7498028542,
               data=(b'\x03\x02\x00\x00\x00\x00\x00\x00\x00@d\x02\x01\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xa4\xd9\x9do\x01\x00\x00\x00'),
               values=(515, 4335091712, 0, 6167583140), tid=7649, debugid=17563693, eventid=17563692, func_qualifier=1),
        Kevent(timestamp=7498028620,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=7649, debugid=17563694, eventid=17563692, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.target == 515
    assert mach.address == 0x102644000
    assert mach.control == 0
    assert mach.state == 0x16f9dd9a4


def test_msc_mach_vm_protect_trap(traces_parser):
    events = [
        Kevent(timestamp=319993982901,
               data=(b'\x03\x02\x00\x00\x00\x00\x00\x00\x00\xc0@k\x01\x00\x00\x00\x00@\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(515, 6094372864, 16384, 0), tid=57703, debugid=17563705, eventid=17563704, func_qualifier=1),
        Kevent(timestamp=319993982995,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=57703, debugid=17563706, eventid=17563704, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.target == 515
    assert mach.address == 0x16b40c000
    assert mach.size == 0x4000
    assert not mach.set_maximum


def test_msc_mach_vm_map_trap(traces_parser):
    events = [
        Kevent(timestamp=319987780136,
               data=(b'\x03\x02\x00\x00\x00\x00\x00\x00hf\xdbm\x01\x00\x00\x00\x00\x80\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(515, 6138062440, 32768, 0), tid=57808, debugid=17563709, eventid=17563708, func_qualifier=1),
        Kevent(timestamp=319987780148,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=57808, debugid=17563710, eventid=17563708, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.target == 515
    assert mach.address == 0x16ddb6668
    assert mach.size == 0x8000
    assert mach.mask == 0


def test_msc_mach_reply_port(traces_parser):
    events = [
        Kevent(timestamp=5453890497755,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=941818, debugid=17563753, eventid=17563752, func_qualifier=1),
        Kevent(timestamp=5453890497771,
               data=(b'\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(771, 0, 0, 0), tid=941818, debugid=17563754, eventid=17563752, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.result == 0x303


def test_msc_thread_self_trap(traces_parser):
    events = [
        Kevent(timestamp=5453890560892,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=941536, debugid=17563757, eventid=17563756, func_qualifier=1),
        Kevent(timestamp=5453890560912,
               data=(b'\x0b\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(42507, 0, 0, 0), tid=941536, debugid=17563758, eventid=17563756, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.result == 0xa60b


def test_msc_task_self_trap(traces_parser):
    events = [
        Kevent(timestamp=5453890600244,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=941827, debugid=17563761, eventid=17563760, func_qualifier=1),
        Kevent(timestamp=5453890600265,
               data=(b'\x03\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(515, 0, 0, 0), tid=941827, debugid=17563762, eventid=17563760, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.result == 515


def test_msc_mach_port_unguard_trap(traces_parser):
    events = [
        Kevent(timestamp=5453890742696,
               data=(b'\x03\x02\x00\x00\x00\x00\x00\x00\x03\x8e\n\x00\x00\x00\x00\x000j\xd2G\x01\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(515, 691715, 5499939376, 0), tid=941734, debugid=17563817, eventid=17563816, func_qualifier=1),
        Kevent(timestamp=5453890742704,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=941734, debugid=17563818, eventid=17563816, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.target == 515
    assert mach.name == 0xa8e03
    assert mach.guard == 0x147d26a30


def test_msc_mach_timebase_info(traces_parser):
    events = [
        Kevent(timestamp=5453890643526,
               data=(b'\xc4F\n\x0e\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(8825489092, 0, 0, 0), tid=941827, debugid=17564005, eventid=17564004, func_qualifier=1),
        Kevent(timestamp=5453890643529,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=941827, debugid=17564006, eventid=17564004, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    mach = ret[0]
    assert mach.info == 0x20e0a46c4


def test_mach_vmfault(traces_parser):
    events = [
        Kevent(timestamp=10533581994269,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x99k\x01\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 6100205568, 0, 0), tid=876421, debugid=19922953, eventid=19922952, func_qualifier=1),
        Kevent(timestamp=10533581994584,
               data=(b'\x00\xc0\x99k\x01\x00\x00\x00\x01\x03\x1e\x00\x00\x00\x00\x00\x00\x00\x08\x00'
                     b'\x00\x00\x00\x00_\x00\x00\x00\x00\x00\x00\x00'),
               values=(6100205568, 1966849, 524288, 95), tid=876421, debugid=20054024, eventid=20054024,
               func_qualifier=0),
        Kevent(timestamp=10533581994616,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x99k\x01\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 6100205568, 0, 1), tid=876421, debugid=19922954, eventid=19922952,
               func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    fault = ret[1]
    assert fault.addr == 0x16b99c000
    assert not fault.is_kernel
    assert fault.result == 0
    assert fault.fault_type == DbgVmFaultType.DBG_ZERO_FILL_FAULT
    assert fault.pid == 95
    assert fault.caller_prot == [VmProtection.VM_PROT_READ, VmProtection.VM_PROT_WRITE]


def test_mach_vmfault_no_real_address(traces_parser):
    events = [
        Kevent(timestamp=10533581994269,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x99k\x01\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 6100205568, 0, 0), tid=876421, debugid=19922953, eventid=19922952, func_qualifier=1),
        Kevent(timestamp=10533581994616,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x99k\x01\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 6100205568, 0, 1), tid=876421, debugid=19922954, eventid=19922952,
               func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    fault = ret[0]
    assert fault.addr == 0x16b99c000
    assert not fault.is_kernel
    assert fault.result == 0
    assert fault.fault_type == DbgVmFaultType.DBG_ZERO_FILL_FAULT
    assert fault.pid is None
    assert fault.caller_prot is None


def test_mach_sched(traces_parser):
    events = [
        Kevent(timestamp=4580000449861,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00o\x02\x00\x00\x00\x00\x00\x00\x04'
                     b'\x00\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 623, 4, 81), tid=387391, debugid=20971520, eventid=20971520, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    sched = ret[0]
    assert sched.reason == [AsynchronousSystemTrapsReason.AST_PREEMPT]
    assert sched.to == 623
    assert sched.from_sched_pri == 4
    assert sched.to_sched_pri == 81


def test_mach_stkhandoff(traces_parser):
    events = [
        Kevent(timestamp=3897242679331,
               data=(b'\x05\x00\x00\x00\x00\x00\x00\x00w\xf5\x04\x00\x00\x00\x00\x007\x00'
                     b'\x00\x00\x00\x00\x00\x00?\x00\x00\x00\x00\x00\x00\x00'),
               values=(5, 324983, 55, 63), tid=2761, debugid=20971528, eventid=20971528, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    handoff = ret[0]
    assert handoff.from_ == 2761
    assert handoff.to == 324983
    assert handoff.reason == [AsynchronousSystemTrapsReason.AST_PREEMPT, AsynchronousSystemTrapsReason.AST_URGENT]
    assert handoff.from_sched_pri == 55
    assert handoff.to_sched_pri == 63


def test_mach_mkrunnable(traces_parser):
    events = [
        Kevent(timestamp=9982171649633,
               data=(b'\xb7\x01\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'),
               values=(439, 81, 0, 8), tid=261, debugid=20971544, eventid=20971544, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    mkrunnable = ret[0]
    assert mkrunnable.tid == 439
    assert mkrunnable.sched_pri == 81
    assert mkrunnable.wait_result == 0
    assert mkrunnable.runnable_threads == 8


def test_mach_idle(traces_parser):
    events = [
        Kevent(timestamp=10071358928388,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=332, debugid=20971557, eventid=20971556, func_qualifier=1),
        Kevent(timestamp=10071358928416,
               data=(b'\xa4\xb1\x0c\x00\x00\x00\x00\x00\xf1\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(831908, 241, 3, 0), tid=332, debugid=27852808, eventid=27852808, func_qualifier=0),
        Kevent(timestamp=10071358928432,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\xa4\xb1\x0c'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 6, 831908, 0), tid=332, debugid=20971558, eventid=20971556, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    idle = ret[1]
    assert idle.from_ == 0
    assert idle.process_state == ProcessState.PROCESSOR_RUNNING
    assert idle.to == 831908
    assert idle.reason == [AsynchronousSystemTrapsReason.AST_NONE]


def test_mach_block(traces_parser):
    events = [
        Kevent(timestamp=4643561352579,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x98\x92n\x07\xf0\xff\xff\xff\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 18446744005114761880, 0, 0), tid=883, debugid=20971580, eventid=20971580, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    block = ret[0]
    assert block.reason == [AsynchronousSystemTrapsReason.AST_NONE]
    assert block.continuation == 0xfffffff0076e9298


def test_mach_wait(traces_parser):
    events = [
        Kevent(timestamp=4365975502717,
               data=(b'\x19\x99\xe5<\xfb\xd5\xa0u\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(8476009773746460953, 0, 0, 0), tid=884, debugid=20971584, eventid=20971584, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    wait = ret[0]
    assert wait.event == 8476009773746460953


def test_mach_dispatch(traces_parser):
    events = [
        Kevent(timestamp=4440978834382,
               data=(b'L\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x84\x00\x00'
                     b'\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'),
               values=(332, 0, 132, 3), tid=261, debugid=20971648, eventid=20971648, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    dispatch = ret[0]
    assert dispatch.tid == 332
    assert dispatch.reason == [AsynchronousSystemTrapsReason.AST_NONE]
    assert dispatch.state == [ThreadState.TH_RUN, ThreadState.TH_IDLE]
    assert dispatch.runnable_threads == 3


def test_thread_group_set(traces_parser):
    events = [
        Kevent(timestamp=10566859835989,
               data=(b'\xff\xff\xff\xff\xff\xff\xff\xff>\x00\x00\x00\x00\x00\x00\x00\xf6l\r\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(18446744073709551615, 62, 879862, 0), tid=879802, debugid=27656200, eventid=27656200,
               func_qualifier=0)]
    ret = list(traces_parser.feed_generator(events))
    group_set = ret[0]
    assert group_set.current_tgid == -1
    assert group_set.target_tgid == 62
    assert group_set.tid == 879862
    assert group_set.home_tgid == 0


def test_sched_clutch_cpu_thread_select(traces_parser):
    events = [
        Kevent(timestamp=4387224443080,
               data=(b'\xa7\xa7\x05\x00\x00\x00\x00\x00\xf1\x00\x00\x00\x00\x00\x00\x00\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(370599, 241, 1, 0), tid=597, debugid=27852808, eventid=27852808, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    select = ret[0]
    assert select.tid == 370599
    assert select.tgid == 241
    assert select.scb_bucket == 1


def test_sched_clutch_tg_bucket_pri(traces_parser):
    events = [
        Kevent(timestamp=4517075147289,
               data=(b'/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00'
                     b'\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00'),
               values=(47, 0, 67, 16), tid=261, debugid=27852816, eventid=27852816, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    pri = ret[0]
    assert pri.tgid == 47
    assert pri.scb_bucket == 0
    assert pri.priority == 67
    assert pri.interactive_score == 16
