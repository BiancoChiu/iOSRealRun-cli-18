from dataclasses import dataclass
from enum import Enum
from itertools import chain
from typing import List, Any


class SamplerAction(Enum):
    SAMPLER_TH_INFO = 0x01
    SAMPLER_TH_SNAPSHOT = 0x02
    SAMPLER_KSTACK = 0x04
    SAMPLER_USTACK = 0x08
    SAMPLER_PMC_THREAD = 0x10
    SAMPLER_PMC_CPU = 0x20
    SAMPLER_PMC_CONFIG = 0x40
    SAMPLER_MEMINFO = 0x80
    SAMPLER_TH_SCHEDULING = 0x100
    SAMPLER_TH_DISPATCH = 0x200
    SAMPLER_TK_SNAPSHOT = 0x400
    SAMPLER_SYS_MEM = 0x800
    SAMPLER_TH_INSCYC = 0x1000
    SAMPLER_TK_INFO = 0x2000


def to_sampler_action(flags: int):
    return [s for s in SamplerAction if s.value & flags]


class KperfTiState(Enum):
    KPERF_TI_RUNNING = 0x01
    KPERF_TI_RUNNABLE = 0x02
    KPERF_TI_WAIT = 0x04
    KPERF_TI_UNINT = 0x08
    KPERF_TI_SUSP = 0x10
    KPERF_TI_TERMINATE = 0x20
    KPERF_TI_IDLE = 0x40


def to_kperf_ti_state(flags: int):
    return [s for s in KperfTiState if s.value & flags]


class CallstackFlag(Enum):
    CALLSTACK_VALID = 0x01
    CALLSTACK_DEFERRED = 0x02
    CALLSTACK_64BIT = 0x04
    CALLSTACK_KERNEL = 0x08
    CALLSTACK_TRUNCATED = 0x10
    CALLSTACK_CONTINUATION = 0x20
    CALLSTACK_KERNEL_WORDS = 0x40
    CALLSTACK_TRANSLATED = 0x80
    CALLSTACK_FIXUP_PC = 0x100


def to_callstack_flags(flags: int):
    return [c for c in CallstackFlag if c.value & flags]


@dataclass
class PerfEvent:
    ktraces: List
    sample_what: List
    actionid: int
    th_info: Any = None
    cs_flags: List = None
    cs_frames: List = None

    def __str__(self):
        sample_what = ' | '.join(map(lambda s: s.name, self.sample_what))
        rep = f'PERF_Event, sample_what: {sample_what}, actionid: {self.actionid}'
        if self.cs_frames is not None:
            rep += f', frames count: {len(self.cs_frames)}'
        return rep


@dataclass
class PerfThdData:
    """
    According to kperf_thread_info_sample, osfmk/kperf/thread_samplers.c
    """
    ktraces: List
    pid: int
    tid: int
    dq_addr: int
    runmode: List

    def __str__(self):
        runmode = ' | '.join(map(lambda r: r.name, self.runmode))
        return f'PERF_THD_Data, pid: {self.pid}, tid: {self.tid}, dq_addr: {hex(self.dq_addr)}, runmode: {runmode}'


@dataclass
class PerfThdCswitch:
    """
    According to kperf_on_cpu_internal, osfmk/kperf/kperf.c
    """
    ktraces: List
    tid: int
    pid: int

    def __str__(self):
        return f'PERF_THD_CSwitch, tid: {self.tid}, pid: {self.pid}'


@dataclass
class PerfStkUdata:
    """
    According to callstack_log, osfmk/kperf/callstack.c
    """
    ktraces: List
    frames: List

    def __str__(self):
        frames = ', '.join(map(hex, self.frames))
        return f'PERF_STK_UData, frames: [{frames}]'


@dataclass
class PerfStkUhdr:
    """
    According to callstack_log, osfmk/kperf/callstack.c
    """
    ktraces: List
    flags: List
    nframes: int

    def __str__(self):
        flags = ' | '.join(map(lambda c: c.name, self.flags))
        return f'PERF_STK_UHdr, flags: {flags}, frames count: {self.nframes}'


def handle_event(parser, events):
    args = events[0].values
    e = PerfEvent(events, to_sampler_action(args[0]), args[1])
    if SamplerAction.SAMPLER_TH_INFO in e.sample_what:
        sub_events = [ev for ev in events if parser.trace_codes.get(ev.eventid, '') == 'PERF_THD_Data']
        if sub_events:
            e.th_info = handle_thd_data(parser, sub_events)
    if SamplerAction.SAMPLER_USTACK in e.sample_what:
        sub_events = [ev for ev in events if parser.trace_codes.get(ev.eventid, '') == 'PERF_STK_UHdr']
        if sub_events:
            header = handle_stk_uhdr(parser, sub_events)
            stk_data = [handle_stk_udata(parser, [ev]).frames for ev in events if
                        parser.trace_codes.get(ev.eventid, '') == 'PERF_STK_UData']
            e.cs_frames = list(chain.from_iterable(stk_data))[:header.nframes]
            e.cs_flags = header.flags

    return e


def handle_thd_data(parser, events):
    args = events[0].values
    pid = args[0]
    tid = args[1]
    parser.threads_pids[tid] = pid
    return PerfThdData(events, pid, tid, args[2], to_kperf_ti_state(args[3] & 0xffff))


def handle_thd_cswitch(parser, events):
    args = events[0].values
    return PerfThdCswitch(events, args[0], args[1])


def handle_stk_udata(parser, events):
    return PerfStkUdata(events, list(events[0].values))


def handle_stk_uhdr(parser, events):
    args = events[0].values
    return PerfStkUhdr(events, to_callstack_flags(args[0]), args[1])


handlers = {
    'PERF_Event': handle_event,
    'PERF_THD_Data': handle_thd_data,
    'PERF_THD_CSwitch': handle_thd_cswitch,
    'PERF_STK_UData': handle_stk_udata,
    'PERF_STK_UHdr': handle_stk_uhdr,
}
