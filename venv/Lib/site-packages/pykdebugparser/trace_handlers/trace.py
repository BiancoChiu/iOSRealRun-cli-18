from dataclasses import dataclass
from typing import List

from pykdebugparser.kevent import DgbFuncQual


@dataclass
class TraceDataNewthread:
    ktraces: List
    tid: int
    pid: int
    is_exec_copy: int
    uniqueid: int

    def __str__(self):
        return f'New thread {self.tid} of parent: {self.pid}'


@dataclass
class TraceDataExec:
    ktraces: List
    pid: int
    fsid: int
    fileid: int

    def __str__(self):
        return f'New process pid: {self.pid}'


@dataclass
class TraceDataThreadTerminate:
    ktraces: List
    tid: int
    pid: int = None
    name: str = ''

    def __str__(self):
        rep = f'Thread terminated tid: {self.tid}'
        if self.pid is not None:
            rep += f', pid: {self.pid}'
        if self.name:
            rep += f', name: {self.name}'
        return rep


@dataclass
class TraceDataThreadTerminatePid:
    ktraces: List
    pid: int
    uniqueid: int

    def __str__(self):
        return f'Thread terminated thread pid: {self.pid}, unique id {self.uniqueid}'


@dataclass
class TraceStringGlobal:
    ktraces: List
    debugid: int
    str_id: int
    vstr: str

    def __str__(self):
        return f'New global string: "{self.vstr}", id: {self.str_id}'


@dataclass
class TraceStringNewthread:
    ktraces: List
    name: str

    def __str__(self):
        return f'New thread of parent: {self.name}'


@dataclass
class TraceStringExec:
    ktraces: List
    name: str

    def __str__(self):
        return f'New process name: {self.name}'


@dataclass
class TraceStringProcExit:
    ktraces: List
    name: str

    def __str__(self):
        return f'Process exit name: {self.name}'


@dataclass
class TraceStringThreadname:
    ktraces: List
    name: str

    def __str__(self):
        return f'New thread name: {self.name}'


@dataclass
class TraceStringThreadnamePrev:
    ktraces: List
    name: str

    def __str__(self):
        return f'Thread terminated name: {self.name}'


def handle_trace_data_newthread(parser, events):
    result = events[0].values
    parser.last_data_newthread = TraceDataNewthread(events, result[0], result[1], result[2], result[3])
    parser.threads_pids[parser.last_data_newthread.tid] = parser.last_data_newthread.pid
    return parser.last_data_newthread


def handle_trace_data_exec(parser, events):
    result = events[0].values
    parser.last_data_exec = TraceDataExec(events, result[0], result[1], result[2])
    return parser.last_data_exec


def handle_trace_data_thread_terminate(parser, events):
    tid = events[0].values[0]
    event = TraceDataThreadTerminate(events, tid, parser.threads_pids.get(tid))
    event.name = parser.tids_names.get(tid, '')
    return event


def handle_trace_data_thread_terminate_pid(parser, events):
    result = events[0].values
    event = TraceDataThreadTerminatePid(events, result[0], result[1])
    parser.threads_pids[events[0].tid] = event.pid
    return event


def handle_trace_string_global(parser, events):
    debugid = 0
    str_id = 0
    vstr = b''
    lookup_events = []
    for event in events:
        lookup_events.append(event)
        if event.func_qualifier & DgbFuncQual.DBG_FUNC_START.value:
            debugid = event.values[0]
            str_id = event.values[1]
            vstr += event.data[16:]
        else:
            vstr += event.data

        if event.func_qualifier & DgbFuncQual.DBG_FUNC_END.value:
            break
    event = TraceStringGlobal(lookup_events, debugid, str_id,
                              vstr.replace(b'\x00', b'').decode(errors='backslashreplace'))
    if event.vstr:
        parser.global_strings[event.str_id] = event.vstr
    return event


def handle_trace_string_newthread(parser, events):
    event = TraceStringNewthread(events, events[0].data.replace(b'\x00', b'').decode())
    parser.pids_names[parser.last_data_newthread.pid] = event.name
    return event


def handle_trace_string_exec(parser, events):
    event = TraceStringExec(events, events[0].data.replace(b'\x00', b'').decode())
    parser.pids_names[parser.last_data_exec.pid] = event.name
    return event


def handle_trace_string_proc_exit(parser, events):
    return TraceStringProcExit(events, events[0].data.replace(b'\x00', b'').decode())


def handle_trace_string_threadname(parser, events):
    name = b''.join([e.data for e in events]).replace(b'\x00', b'').decode()
    event = TraceStringThreadname(events, name)
    parser.tids_names[events[0].tid] = event.name
    return event


def handle_trace_string_threadname_prev(parser, events):
    name = b''.join([e.data for e in events]).replace(b'\x00', b'').decode()
    event = TraceStringThreadnamePrev(events, name)
    parser.tids_names[events[0].tid] = event.name
    return event


handlers = {
    'TRACE_DATA_NEWTHREAD': handle_trace_data_newthread,
    'TRACE_DATA_EXEC': handle_trace_data_exec,
    'TRACE_DATA_THREAD_TERMINATE': handle_trace_data_thread_terminate,
    'TRACE_DATA_THREAD_TERMINATE_PID': handle_trace_data_thread_terminate_pid,
    'TRACE_STRING_GLOBAL': handle_trace_string_global,
    'TRACE_STRING_NEWTHREAD': handle_trace_string_newthread,
    'TRACE_STRING_EXEC': handle_trace_string_exec,
    'TRACE_STRING_PROC_EXIT': handle_trace_string_proc_exit,
    'TRACE_STRING_THREADNAME': handle_trace_string_threadname,
    'TRACE_STRING_THREADNAME_PREV': handle_trace_string_threadname_prev,
}
