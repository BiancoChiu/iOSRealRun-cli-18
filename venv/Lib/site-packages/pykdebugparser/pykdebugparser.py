from datetime import datetime
import io

from pygments import highlight, lexers, formatters
from termcolor import colored

from pykdebugparser.callstacks_parser import CallstacksParser
from pykdebugparser.kd_buf_parser import KdBufParser
from pykdebugparser.kevent import DgbFuncQual
from pykdebugparser.trace_codes import default_trace_codes
from pykdebugparser.traces_parser import TracesParser
from pykdebugparser.os_log_event import OsLogEvent

c_lexer = lexers.CLexer()
color_formatter = formatters.TerminalTrueColorFormatter(style='stata-dark')

DBG_TRACE = 7
DBG_FSYSTEM = 3
DBG_BSD = 4


class PyKdebugParser:
    def __init__(self):
        self.filter_tid = None
        self.filter_process = None
        self.filter_class = []
        self.filter_subclass = []
        self.show_timestamp = True
        self.show_name = True
        self.show_func_qual = True
        self.show_tid = False
        self.show_process = True
        self.show_args = True
        self.color = True
        self.numer = None
        self.denom = None
        self.mach_absolute_time = None
        self.usecs_since_epoch = None
        self.timezone = None
        self.threads_pids = {}
        self.pids_names = {}
        self.dyld_addresses = []
        self.dyld_uuids = []

    def kevents(self, kdebug: io.IOBase):
        events_generator = KdBufParser(self.threads_pids, self.pids_names).parse(kdebug)
        events_generator = filter(lambda e: not isinstance(e, OsLogEvent), events_generator)
        if self.filter_tid is not None:
            events_generator = filter(lambda e: e.tid == self.filter_tid, events_generator)
        if self.filter_class or self.filter_subclass:
            events_generator = filter(lambda e: self._is_eventid_allowed(e.eventid), events_generator)
        return events_generator

    def formatted_kevents(self, kdebug: io.IOBase, trace_codes=None):
        trace_codes_map = default_trace_codes() if trace_codes is None else trace_codes
        return map(lambda e: self._format_kevent(e, trace_codes_map), self.kevents(kdebug))

    def traces(self, kdebug: io.IOBase, trace_codes=None):
        trace_codes_map = default_trace_codes() if trace_codes is None else trace_codes

        has_filters = self.filter_class or self.filter_subclass
        add_trace_class = has_filters and DBG_TRACE not in self.filter_class
        if add_trace_class:
            self.filter_class.append(DBG_TRACE)
        has_bsd = DBG_BSD in self.filter_class or any(filter(lambda sc: sc >> 8 == DBG_BSD, self.filter_subclass))
        add_fs_class = has_filters and has_bsd and DBG_FSYSTEM not in self.filter_class
        if add_fs_class:
            self.filter_class.append(DBG_FSYSTEM)

        traces_parser = TracesParser(trace_codes_map, self.threads_pids, self.pids_names)
        trace_generator = traces_parser.feed_generator(self.kevents(kdebug))

        if self.filter_process is not None:
            trace_generator = filter(self._filter_process_callback, trace_generator)
        if add_trace_class:
            trace_generator = filter(lambda t: t.ktraces[0].eventid >> 24 != DBG_TRACE, trace_generator)
        if add_fs_class:
            trace_generator = filter(lambda t: t.ktraces[0].eventid >> 24 != DBG_FSYSTEM, trace_generator)
        return trace_generator

    def formatted_traces(self, kdebug: io.IOBase, trace_codes=None):
        return map(lambda t: self._format_trace(t), self.traces(kdebug, trace_codes))

    def callstacks(self, kdebug: io.IOBase, trace_codes=None):
        callstacks_parser = CallstacksParser(self.dyld_addresses, self.dyld_uuids)
        return callstacks_parser.feed_generator(self.traces(kdebug, trace_codes))

    def formatted_callstacks(self, kdebug: io.IOBase, trace_codes=None):
        return map(lambda t: self._format_callstack(t), self.callstacks(kdebug, trace_codes))

    def os_log_events(self, kdebug: io.IOBase):
        events_generator = KdBufParser(self.threads_pids, self.pids_names).parse(kdebug)
        events_generator = filter(lambda e: isinstance(e, OsLogEvent), events_generator)
        if self.filter_tid is not None:
            events_generator = filter(lambda e: e.thread_identifier == self.filter_tid, events_generator)
        if self.filter_process is not None:
            events_generator = filter(lambda e: self.filter_process in (e.process, str(e.process_identifier)),
                                      events_generator)
        return events_generator

    def formatted_logs(self, kdebug: io.IOBase):
        return map(lambda t: self._format_log(t), self.os_log_events(kdebug))

    def _filter_process_callback(self, trace):
        tid = trace.ktraces[0].tid
        pid = self.threads_pids.get(tid, -1)
        process_name = self.pids_names.get(pid, '')
        return self.filter_process == str(pid) or self.filter_process == process_name

    def _format_timestamp(self, timestamp):
        if None in (self.mach_absolute_time, self.numer, self.denom, self.usecs_since_epoch, self.timezone):
            return str(timestamp) + ' '
        offset_usec = (
                ((timestamp - self.mach_absolute_time) * self.numer) / (self.denom * 1000)
        )
        ts = datetime.fromtimestamp((self.usecs_since_epoch + offset_usec) / 1000000, tz=self.timezone)
        time_string = ts.strftime('%Y-%m-%d %H:%M:%S.%f')
        return f'{time_string:<27}'

    def _format_process(self, tid):
        pid = self.threads_pids.get(tid, -1)
        process_name = self.pids_names.get(pid, '')
        return f'{process_name}({pid})' if pid != -1 else f'Error: tid {tid}'

    def _format_kevent(self, event, trace_codes_map):
        tid = event.tid
        if event.eventid in trace_codes_map:
            name = trace_codes_map[event.eventid] + f' ({hex(event.eventid)})'
        else:
            # Some event IDs are not public.
            name = hex(event.eventid)
        formatted_data = ''
        if self.show_timestamp:
            formatted_data += self._format_timestamp(event.timestamp)
        formatted_data += f'{name:<58}' if self.show_name else ''
        if self.show_func_qual:
            try:
                formatted_data += f'{DgbFuncQual(event.func_qualifier).name:<15}'
            except ValueError:
                formatted_data += f'''{'Error':<16}'''
        formatted_data += f'{hex(tid):<12}' if self.show_tid else ''
        if self.show_process:
            formatted_data += f'{self._format_process(tid):<27}'
        formatted_data += f'{str(event.data):<34}' if self.show_args else ''
        return formatted_data

    def _format_trace(self, trace):
        tid = trace.ktraces[0].tid
        formatted_data = ''
        if self.show_timestamp:
            formatted_data += self._format_timestamp(trace.ktraces[0].timestamp)
        formatted_data += f'{tid:>11} ' if self.show_tid else ''
        if self.show_process:
            formatted_data += f'{self._format_process(tid):<34}'
        event_rep = str(trace)
        if self.color:
            event_rep = highlight(event_rep, c_lexer, color_formatter).strip()

        return formatted_data + event_rep

    def _format_callstack(self, callstack):
        tid = callstack.tid
        formatted_data = ''
        if self.show_timestamp:
            formatted_data += self._format_timestamp(callstack.timestamp)
        formatted_data += f'{tid:>11} ' if self.show_tid else ''
        if self.show_process:
            formatted_data += f'{self._format_process(tid):<34}'
        ret = [formatted_data]
        for i, frame in enumerate(callstack.frames):
            line = f'{frame.uuid}:0x{frame.offset:016x}' if frame.uuid is not None else f'0x{frame.address:016x}'
            ret.append((' ' * i) + line)
        return '\n'.join(ret)

    def _format_log(self, os_log: OsLogEvent):
        time_string = os_log.unix_date.strftime('%Y-%m-%d %H:%M:%S.%f')
        timestamp = f'{time_string:<27}'
        event_rep = colored(str(timestamp), 'green') if self.color else str(timestamp)
        if os_log.process:
            process = self._format_process(os_log.thread_identifier)
            process = colored(process, 'magenta') if self.color else process
            event_rep += f' {process:<27} '
        event_rep += colored(os_log.composed_message, 'white') if self.color else os_log.composed_message
        return event_rep

    def _is_eventid_allowed(self, event_id):
        return (event_id >> 24 in self.filter_class) or (event_id >> 16 in self.filter_subclass)
