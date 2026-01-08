from dataclasses import dataclass, field
from datetime import datetime, timezone
import enum
from typing import List, Dict

from construct import Struct, Byte, Int32ul, BitStruct, Padding, Flag, BitsInteger, Int64ul


class OsLogType(enum.Enum):
    DEFAULT = 0
    INFO = 1
    DEBUG = 2
    ERROR = 0x10
    FAULT = 0x11


class FirehoseTracepointNamespace(enum.Enum):
    unknown = 0
    activity = 2
    trace = 3
    log = 4
    metadata = 5
    signpost = 6
    loss = 7


class FirehoseTracepointFlagsPcStyle(enum.Enum):
    none = 0
    main_exe = 1
    shared_cache = 2
    main_plugin = 3
    absolute = 4
    uuid_relative = 5
    large_shared_cache = 6
    _unused7 = 7


class FirehoseTracepointActivityType(enum.Enum):
    create = 1
    swap = 2
    useraction = 3


class FirehoseTracepointTraceType(enum.Enum):
    default = 0
    info = 1
    debug = 2
    error = 0x10
    fault = 0x11


class FirehoseTracepointLogType(enum.Enum):
    default = 0
    info = 1
    debug = 2
    error = 0x10
    fault = 0x11


class FirehoseTracepointLogFlags(enum.IntFlag):
    has_private_data = 1
    has_subsystem = 2
    has_rules = 4
    has_oversize = 8
    has_context_data = 0x10


class FirehoseTracepointMetadataType(enum.Enum):
    dyld = 1
    subsystem = 2
    kext = 3
    coprocessor = 4


class FirehoseTracepointSignpostType(enum.IntFlag):
    event = 0
    interval_begin = 1
    interval_end = 2
    scope_thread = 0x40
    scope_process = 0x80
    scope_system = 0xc0


class FirehoseTracepointSingpostFlags(enum.Enum):
    has_private_data = 1
    has_subsystem = 2
    has_rules = 4
    has_oversize = 8
    has_context_data = 0x10
    has_name = 0x80


tracepoint_types = {
    FirehoseTracepointNamespace.activity: FirehoseTracepointActivityType,
    FirehoseTracepointNamespace.trace: FirehoseTracepointTraceType,
    FirehoseTracepointNamespace.log: FirehoseTracepointLogType,
    FirehoseTracepointNamespace.metadata: FirehoseTracepointMetadataType,
    FirehoseTracepointNamespace.signpost: FirehoseTracepointSignpostType,
}

tracepoint_flags = {
    FirehoseTracepointNamespace.log: FirehoseTracepointLogFlags,
    FirehoseTracepointNamespace.trace: FirehoseTracepointSingpostFlags,
}

firehose_tracepoint_id = Struct(
    'namespace' / Byte,
    'type_' / Byte,
    'trace_flags' / BitStruct(
        Padding(2),
        'has_large_offset' / Flag,
        'has_unique_pid' / Flag,
        'pc_style' / BitsInteger(3),
        'has_current_aid' / Flag,
    ),
    'flags' / Byte,
    'code' / Int32ul,
)


@dataclass
class TraceIdentifier:
    namespace: FirehoseTracepointNamespace
    type_: enum.Enum
    has_large_offset: bool
    has_unique_pid: bool
    pc_style: FirehoseTracepointFlagsPcStyle
    has_current_aid: bool
    flags: None
    code: int


@dataclass
class OsLogEvent:
    composed_message: str
    type_: str
    size: str
    thread_identifier: int
    continuous_nanoseconds_since_boot: int
    mach_continuous_timestamp: int
    boot_uuid: bytes
    process_image_uuid: bytes
    unix_date: datetime
    unix_timezone: Dict
    process_image_path: str = ''
    process: str = ''
    sender_image_path: str = ''
    sender: str = ''
    sender_image_offset: int = 0
    sender_image_uuid: bytes = b''
    log_type: OsLogType = None
    time_to_live: int = 0
    process_identifier: int = 0
    subsystem: str = ''
    category: str = ''
    format_string: str = ''
    activity_identifier: int = 0
    parent_activity_identifier: int = 0
    decomposed_message: Dict = field(default_factory=dict)
    trace_identifier: TraceIdentifier = None
    creator_activity_identifier: int = 0
    creator_process_unique_identifier: int = 0
    signpost_identifier: int = 0
    signpost_name: str = ''
    signpost_type: int = 0
    signpost_scope: int = 0
    loss_start_mach_continuous_timestamp: int = 0
    loss_end_mach_continuous_timestamp: int = 0
    loss_start_unix_date: Dict = field(default_factory=dict)
    loss_end_unix_date: Dict = field(default_factory=dict)
    loss_start_unix_timezone: Dict = field(default_factory=dict)
    loss_end_unix_timezone: Dict = field(default_factory=dict)
    loss_count: Dict = field(default_factory=dict)
    backtrace: List = field(default_factory=list)

    @classmethod
    def from_raw_log_event(cls, event, log_strings):
        parsed_event = {
            'composed_message': log_strings[event.pop('cm')],
            'type_': event.pop('t'),
            'size': event.pop('s'),
            'thread_identifier': event.pop('tid'),
            'continuous_nanoseconds_since_boot': event.pop('ns'),
            'mach_continuous_timestamp': event.pop('mct'),
            'boot_uuid': event.pop('b'),
            'process_image_uuid': event.pop('piu'),
        }
        unix_date = event.pop('ud')
        parsed_event['unix_date'] = datetime.fromtimestamp(unix_date['sec'] + (unix_date['usec'] / 10 ** 6),
                                                           tz=timezone.utc)
        utz = event.pop('utz')
        parsed_event['unix_timezone'] = {'minutes_west': utz['mw'], 'dst_time': utz['dt']}
        if 'ti' in event:
            parsed_event['trace_identifier'] = cls.parse_trace_identifier(event.pop('ti'))
        if 'pip' in event:
            parsed_event['process_image_path'] = log_strings[event.pop('pip')]
        if 'p' in event:
            parsed_event['process'] = log_strings[event.pop('p')]
        if 'sip' in event:
            parsed_event['sender_image_path'] = log_strings[event.pop('sip')]
        if 'send' in event:
            parsed_event['sender'] = log_strings[event.pop('send')]
        if 'sio' in event:
            parsed_event['sender_image_offset'] = event.pop('sio')
        if 'siu' in event:
            parsed_event['sender_image_uuid'] = event.pop('siu')
        if 'lt' in event:
            parsed_event['log_type'] = OsLogType(event.pop('lt'))
        if 'ttl' in event:
            parsed_event['time_to_live'] = event.pop('ttl')
        if 'pid' in event:
            parsed_event['process_identifier'] = event.pop('pid')
        if 'aid' in event:
            parsed_event['activity_identifier'] = event.pop('aid')
        if 'paid' in event:
            parsed_event['parent_activity_identifier'] = event.pop('paid')
        if 'tai' in event:
            parsed_event['transition_activity_identifier'] = event.pop('tai')
        if 'sub' in event:
            parsed_event['subsystem'] = log_strings[event.pop('sub')]
        if 'cat' in event:
            parsed_event['category'] = log_strings[event.pop('cat')]
        if 'f' in event:
            parsed_event['format_string'] = log_strings[event.pop('f')]
        if 'cai' in event:
            parsed_event['creator_activity_identifier'] = event.pop('cai')
        if 'cpui' in event:
            parsed_event['creator_process_unique_identifier'] = event.pop('cpui')
        if 'si' in event:
            parsed_event['signpost_identifier'] = event.pop('si')
        if 'sn' in event:
            parsed_event['signpost_name'] = log_strings[event.pop('sn')]
        if 'st' in event:
            parsed_event['signpost_type'] = event.pop('st')
        if 'ss' in event:
            parsed_event['signpost_scope'] = event.pop('ss')
        if 'lsmct' in event:
            parsed_event['loss_start_mach_continuous_timestamp'] = event.pop('lsmct')
        if 'lemct' in event:
            parsed_event['loss_end_mach_continuous_timestamp'] = event.pop('lemct')
        if 'lsud' in event:
            parsed_event['loss_start_unix_date'] = event.pop('lsud')
        if 'leud' in event:
            parsed_event['loss_end_unix_date'] = event.pop('leud')
        if 'lsutz' in event:
            utz = event.pop('lsutz')
            parsed_event['loss_start_unix_timezone'] = {'minutes_west': utz['mw'], 'dst_time': utz['dt']}
        if 'leutz' in event:
            utz = event.pop('leutz')
            parsed_event['loss_end_unix_timezone'] = {'minutes_west': utz['mw'], 'dst_time': utz['dt']}
        if 'bt' in event:
            parsed_event['backtrace'] = [
                {'image_uuid': level['iu'], 'image_offset': level['io']}
                for level in event.pop('bt')
            ]
        if 'lc' in event:
            lc = event.pop('lc')
            parsed_event['loss_count'] = {'count': lc['c'], 'unknown': lc['s']}
        if 'dm' in event:
            parsed_event['decomposed_message'] = cls.parse_decomposed(event.pop('dm'), log_strings)
        return OsLogEvent(**parsed_event)

    @classmethod
    def parse_trace_identifier(cls, trace_identifier):
        trace_id = firehose_tracepoint_id.parse(Int64ul.build(trace_identifier))
        trace_namespace = FirehoseTracepointNamespace(trace_id.namespace)
        if trace_namespace in tracepoint_types:
            type_ = tracepoint_types[trace_namespace](trace_id.type_)
        elif trace_namespace == FirehoseTracepointNamespace.signpost:
            type_ = FirehoseTracepointSignpostType(trace_id.type_ & 0xc0) | FirehoseTracepointSignpostType(
                trace_id.type_ & 0x3f)
        else:
            type_ = trace_id.type_

        return TraceIdentifier(
            namespace=trace_namespace,
            type_=type_,
            has_large_offset=trace_id.trace_flags.has_large_offset,
            has_unique_pid=trace_id.trace_flags.has_unique_pid,
            pc_style=FirehoseTracepointFlagsPcStyle(trace_id.trace_flags.pc_style),
            has_current_aid=trace_id.trace_flags.has_current_aid,
            flags=tracepoint_flags[trace_namespace](
                trace_id.flags) if trace_namespace in tracepoint_flags else None,
            code=trace_id.code,
        )

    @classmethod
    def parse_decomposed(cls, decomposed, log_strings):
        parsed_decomposed = {'placeholder_count': decomposed['pc'], 'state': decomposed['s']}
        if not parsed_decomposed['placeholder_count']:
            return parsed_decomposed
        parsed_decomposed['segments'] = [cls.parse_decomposed_segment(seg, log_strings) for seg in decomposed['seg']]
        return parsed_decomposed

    @classmethod
    def parse_decomposed_segment(cls, segment, log_strings):
        parsed_segment = {}
        if 'lp' in segment:
            parsed_segment['literal_prefix'] = log_strings[segment['lp']]
        if 'p' in segment:
            parsed_placeholder = {}
            if 'rs' in segment['p']:
                parsed_placeholder['raw_string'] = log_strings[segment['p']['rs']]
            if 't' in segment['p'] and segment['p']['t']:
                parsed_placeholder['tokens'] = [log_strings[token] for token in segment['p']['t']]
            if 'tn' in segment['p']:
                parsed_placeholder['type_namespace'] = log_strings[segment['p']['tn']]
            if 'ty' in segment['p']:
                parsed_placeholder['type'] = log_strings[segment['p']['ty']]
            parsed_placeholder['width'] = segment['p']['w']
            parsed_placeholder['precision'] = segment['p']['p']
            parsed_segment['placeholder'] = parsed_placeholder
        if 'a' in segment:
            parsed_arg = {}
            if 'a' in segment['a']:
                parsed_arg['availability'] = segment['a']['a']
            if 'p' in segment['a']:
                parsed_arg['privacy'] = segment['a']['p']
            if 'c' in segment['a']:
                parsed_arg['category'] = segment['a']['c']
            if parsed_arg['category'] == 1:
                if 'sc' in segment['a']:
                    parsed_arg['scalar_category'] = segment['a']['sc']
                if 'st' in segment['a']:
                    parsed_arg['scalar_type'] = segment['a']['st']
            if 'availability' not in parsed_arg or parsed_arg['availability'] == 3:
                if 'or' in segment['a']:
                    if parsed_arg['category'] == 2:
                        parsed_arg['object_representation'] = log_strings[segment['a']['or']]
                    else:
                        parsed_arg['object_representation'] = segment['a']['or']
            parsed_segment['arg'] = parsed_arg
        return parsed_segment

    def __str__(self):
        return f'{self.process}{{{self.sender}}}[{self.process_identifier}] {self.composed_message}'
