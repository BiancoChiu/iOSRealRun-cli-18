from collections import namedtuple

from pykdebugparser.kevent import DgbFuncQual
from pykdebugparser.trace_handlers.bsd import handlers as bsd_handlers
from pykdebugparser.trace_handlers.dyld import handlers as dyld_handlers
from pykdebugparser.trace_handlers.fsystem import handlers as fsystem_handlers
from pykdebugparser.trace_handlers.mach import handlers as mach_handlers
from pykdebugparser.trace_handlers.perf import handlers as perf_handlers
from pykdebugparser.trace_handlers.trace import handlers as trace_handlers
from pykdebugparser.trace_handlers.turnstile import handlers as turnstile_handlers

Vnode = namedtuple('Vnode', ['ktraces', 'vnode_id', 'path'])


class TracesParser:
    def __init__(self, trace_codes_map, threads_pids, pids_names):
        self.trace_codes = trace_codes_map
        self.on_going_events = {}
        self.on_going_traces = {}
        self.global_strings = {}
        self.threads_pids = threads_pids
        self.pids_names = pids_names
        self.tids_names = {}
        self.qualifiers_actions = {
            DgbFuncQual.DBG_FUNC_START.value: self._feed_start_event,
            DgbFuncQual.DBG_FUNC_END.value: self._feed_end_event,
            DgbFuncQual.DBG_FUNC_ALL.value: self._feed_single_event,
            DgbFuncQual.DBG_FUNC_NONE.value: self._feed_single_event,
        }
        self.last_data_newthread = None
        self.last_data_exec = None
        self.handlers = {}
        self.handlers.update(bsd_handlers)
        self.handlers.update(dyld_handlers)
        self.handlers.update(fsystem_handlers)
        self.handlers.update(mach_handlers)
        self.handlers.update(perf_handlers)
        self.handlers.update(trace_handlers)
        self.handlers.update(turnstile_handlers)

    def feed(self, event):
        if event.eventid in self.trace_codes:
            trace_name = self.trace_codes[event.eventid]
            if trace_name in trace_handlers:
                return self.qualifiers_actions[event.func_qualifier](event, self.on_going_traces)

        return self.qualifiers_actions[event.func_qualifier](event, self.on_going_events)

    def feed_generator(self, generator):
        for event in generator:
            ret = self.feed(event)
            if ret is not None:
                yield ret

    def parse_event_list(self, events):
        if events[0].eventid not in self.trace_codes:
            return None
        trace_name = self.trace_codes[events[0].eventid]
        if trace_name not in self.handlers:
            return None
        return self.handlers[trace_name](self, events)

    @staticmethod
    def vnode_generator(events):
        path = b''
        vnodeid = 0
        lookup_events = []
        for event in events:
            lookup_events.append(event)
            if event.func_qualifier & DgbFuncQual.DBG_FUNC_START.value:
                vnodeid = event.values[0]
                path += event.data[8:]
            else:
                path += event.data

            if event.func_qualifier & DgbFuncQual.DBG_FUNC_END.value:
                yield Vnode(lookup_events, vnodeid, path.replace(b'\x00', b'').decode())
                path = b''
                vnodeid = 0
                lookup_events = []

    def parse_vnode(self, events):
        try:
            return self.parse_vnodes(events)[0]
        except IndexError:
            return Vnode([], 0, '')

    def parse_vnodes(self, events):
        return list(self.vnode_generator([e for e in events if self.trace_codes.get(e.eventid) == 'VFS_LOOKUP']))

    def _feed_start_event(self, event, state):
        if event.tid not in state:
            # New tid
            state[event.tid] = {}

        state[event.tid][event.eventid] = []
        for eventid in state[event.tid]:
            state[event.tid][eventid].append(event)

    def _feed_end_event(self, event, state):
        if event.tid not in state or event.eventid not in state[event.tid]:
            # Event end without start.
            return

        for eventid in state[event.tid]:
            state[event.tid][eventid].append(event)

        events = state[event.tid].pop(event.eventid)
        return self.parse_event_list(events)

    def _feed_single_event(self, event, state):
        for eventid in state.get(event.tid, {}):
            state[event.tid][eventid].append(event)
        return self.parse_event_list([event])
