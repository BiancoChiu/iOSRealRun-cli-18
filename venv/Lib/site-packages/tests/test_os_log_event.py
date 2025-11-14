from datetime import datetime, timezone

from pykdebugparser.os_log_event import OsLogEvent, OsLogType, FirehoseTracepointNamespace, FirehoseTracepointLogType, \
    FirehoseTracepointFlagsPcStyle, FirehoseTracepointLogFlags


def test_parsing_raw_log_event():
    raw_event = {
        'p': 1101,
        'utz': {
            'mw': 480,
            'dt': 1
        },
        'sub': 11,
        'tid': 2263,
        'ns': 59245485166,
        'dm': {
            's': 0,
            'seg': [
                {
                    'lp': 2013,
                    'p': {
                        'rs': 2014,
                        'w': 0,
                        'p': 0,
                        't': [
                            33
                        ]
                    },
                    'a': {
                        'p': 1,
                        'c': 2,
                        'or': 164
                    }
                },
                {
                    'lp': 2056,
                    'p': {
                        'rs': 2057,
                        'w': 0,
                        'p': 72,
                        'ty': 2059,
                        'tn': 2018,
                        't': [
                            33,
                            2058
                        ]
                    },
                    'a': {
                        'p': 1,
                        'c': 3,
                        'or': (b'\\x02\\x01\\x01\\x00I\\x01\\x00\\x00\\xea2\\x00\\x00\\x00\\x00\\x00\\x00\\xb8\\x08'
                               b'\\r\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00'
                               b'\\x00\\x00\\x00\\x00\\x00P6\\x18\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
                               b'\\x00\\x00\\x0086\\x18\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
                               b'\\x00')
                    }
                }
            ],
            'pc': 2
        },
        'sip': 1100,
        'mct': 1421891644,
        's': 105,
        'siu': b'\\xc4\\x9e\\x0c:\\xa9\\xc3:\\xb9\\x95\\xc4$b\\x80\\xf9#M',
        'f': 2055,
        't': 1024,
        'pip': 1100,
        'lt': 1,
        'piu': b'\\xc4\\x9e\\x0c:\\xa9\\xc3:\\xb9\\x95\\xc4$b\\x80\\xf9#M',
        'cm': 2053,
        'ud': {
            'sec': 1633872873,
            'usec': 810447
        },
        'send': 1101,
        'cat': 2054,
        'pid': 70,
        'sio': 11269856,
        'ti': 101451216374071556,
        'b': b'l\\x87\\xdc\\xbf\\x06\\x01C[\\xbf\\x87\\xcc\\xf4\\xce\\x98\\x16 '
    }

    log_strings = {
        2053: '{\"msg\":\"received AOP log\", \"log\":{\"flags\":1,\"seq\":329,\"data\":[13034]}}',
        1100: '/usr/libexec/locationd',
        1101: 'locationd',
        1024: '/usr/sbin/bluetoothd',
        105: '%25s:%-5d %s: mActiveHighPriorityClientCount: %u, mActiveMediumPriorityClientCount: %u',
        11: 'com.apple.locationd.Motion',
        2054: 'AOP',
        2055: '{\"msg%{public}.0s\":\"received AOP log\", \"log\":%{public, location:CMMotionCoprocessorReply_Log}.*P}',
        2013: '{\"msg',
        2014: '%{public}.0s',
        33: 'public',
        164: '',
        2056: '\":\"received AOP log\", \"log\":',
        2057: '%{public, location:CMMotionCoprocessorReply_Log}.*P',
        2058: 'location:CMMotionCoprocessorReply_Log',
        2018: 'location',
        2059: 'CMMotionCoprocessorReply_Log',
    }

    parsed_event = OsLogEvent.from_raw_log_event(raw_event, log_strings)
    assert parsed_event.process == 'locationd'
    assert parsed_event.unix_timezone == {'minutes_west': 480, 'dst_time': 1}
    assert parsed_event.subsystem == 'com.apple.locationd.Motion'
    assert parsed_event.thread_identifier == 2263
    assert parsed_event.continuous_nanoseconds_since_boot == 59245485166

    assert parsed_event.sender_image_path == '/usr/libexec/locationd'
    assert parsed_event.mach_continuous_timestamp == 1421891644
    assert parsed_event.size == 105
    assert parsed_event.sender_image_uuid == b'\\xc4\\x9e\\x0c:\\xa9\\xc3:\\xb9\\x95\\xc4$b\\x80\\xf9#M'
    assert parsed_event.format_string == ('{"msg%{public}.0s":"received AOP log", "log":%'
                                          '{public, location:CMMotionCoprocessorReply_Log}.*P}')
    assert parsed_event.type_ == 1024
    assert parsed_event.process_image_path == '/usr/libexec/locationd'
    assert parsed_event.log_type == OsLogType.INFO
    assert parsed_event.process_image_uuid == b'\\xc4\\x9e\\x0c:\\xa9\\xc3:\\xb9\\x95\\xc4$b\\x80\\xf9#M'
    assert parsed_event.composed_message == '{"msg":"received AOP log", "log":{"flags":1,"seq":329,"data":[13034]}}'
    assert parsed_event.unix_date == datetime(2021, 10, 10, 13, 34, 33, 810447, tzinfo=timezone.utc)
    assert parsed_event.sender == 'locationd'
    assert parsed_event.category == 'AOP'
    assert parsed_event.process_identifier == 70
    assert parsed_event.sender_image_offset == 11269856
    assert parsed_event.trace_identifier.namespace == FirehoseTracepointNamespace.log
    assert parsed_event.trace_identifier.type_ == FirehoseTracepointLogType.info
    assert not parsed_event.trace_identifier.has_large_offset
    assert not parsed_event.trace_identifier.has_unique_pid
    assert parsed_event.trace_identifier.pc_style == FirehoseTracepointFlagsPcStyle.main_exe
    assert not parsed_event.trace_identifier.has_current_aid
    assert parsed_event.trace_identifier.flags == FirehoseTracepointLogFlags.has_subsystem
    assert parsed_event.boot_uuid == b'l\\x87\\xdc\\xbf\\x06\\x01C[\\xbf\\x87\\xcc\\xf4\\xce\\x98\\x16 '


def test_parsing_event_with_backtrace():
    raw_event = {
        'p': 191,
        'utz': {'mw': 480, 'dt': 1},
        'sub': 192,
        'tid': 1117540,
        'ns': 589505000739000,
        'bt': [
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 1264156},
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 46724},
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 29436},
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 29160},
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 1082752},
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 1082296},
            {'iu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'io': 1081596},
            {'iu': b'\xe8\xa6\x00Q\x0ch5\xae\xae\xfd\x9d\x97\xcc\x7f&\x96', 'io': 66784},
            {'iu': b'\xe8\xa6\x00Q\x0ch5\xae\xae\xfd\x9d\x97\xcc\x7f&\x96', 'io': 67844},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 14864},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 129188},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 44932},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 132596},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 44932},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 48144},
            {'iu': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'io': 90904},
            {'iu': b'\xbc\x1c\xe0\xc6\xa9\xf29k\x9a\xfbb=:\xcdX\x81', 'io': 4528},
            {'iu': b'\xbc\x1c\xe0\xc6\xa9\xf29k\x9a\xfbb=:\xcdX\x81', 'io': 3920}
        ],
        'sip': 190,
        'mct': 14148120017736,
        'dm': {
            's': 0,
            'seg': [
                {'p': {'rs': 100, 'w': 0, 'p': 0}, 'a': {'p': 1, 'c': 2, 'or': 11448}},
                {'lp': 11449, 'p': {'rs': 196, 'w': 0, 'p': 0, 't': [17]}, 'a': {'p': 1, 'c': 2, 'or': 498}}
            ],
            'pc': 2
        },
        's': 270,
        'siu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\',
        'f': 11447,
        't': 1024,
        'ttl': 14,
        'aid': 442,
        'pip': 190,
        'lt': 17,
        'piu': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\',
        'cm': 11446,
        'ud': {'sec': 1634714583, 'usec': 341124},
        'send': 191,
        'cat': 126,
        'pid': 118,
        'sio': 1264156,
        'ti': 7433102699991300,
        'b': b'\x08\xcc\xed\xc6g\xb8O\xe9\xa4\xf0\xa8d\xa0\xba^\x1e'
    }

    log_strings = {
        191: 'corespeechd',
        11446: ('-[CSFallbackAudioSessionReleaseProvider '
                'fallbackDeactivateAudioSession:error:] Cannot deactivateAudioSession with (null)'),
        190: '/System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd',
        192: 'com.apple.corespeech',
        126: 'Framework',
        11447: '%s Cannot deactivateAudioSession with %{public}@',
        100: '%s',
        11448: '-[CSFallbackAudioSessionReleaseProvider fallbackDeactivateAudioSession:error:]',
        11449: ' Cannot deactivateAudioSession with',
        196: '%{public}@',
        17: 'public',
        498: '',
    }

    parsed_event = OsLogEvent.from_raw_log_event(raw_event, log_strings)

    assert parsed_event.process == 'corespeechd'
    assert parsed_event.unix_timezone == {'dst_time': 1, 'minutes_west': 480}
    assert parsed_event.subsystem == 'com.apple.corespeech'
    assert parsed_event.thread_identifier == 1117540
    assert parsed_event.continuous_nanoseconds_since_boot == 589505000739000
    assert parsed_event.backtrace == [
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 1264156},
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 46724},
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 29436},
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 29160},
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 1082752},
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 1082296},
        {'image_uuid': b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\', 'image_offset': 1081596},
        {'image_uuid': b'\xe8\xa6\x00Q\x0ch5\xae\xae\xfd\x9d\x97\xcc\x7f&\x96', 'image_offset': 66784},
        {'image_uuid': b'\xe8\xa6\x00Q\x0ch5\xae\xae\xfd\x9d\x97\xcc\x7f&\x96', 'image_offset': 67844},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 14864},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 129188},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 44932},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 132596},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 44932},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 48144},
        {'image_uuid': b'\x95\x9c\xd6\xe4\x0c\xe70"\xb7<\x8b6\xf7\x9fGE', 'image_offset': 90904},
        {'image_uuid': b'\xbc\x1c\xe0\xc6\xa9\xf29k\x9a\xfbb=:\xcdX\x81', 'image_offset': 4528},
        {'image_uuid': b'\xbc\x1c\xe0\xc6\xa9\xf29k\x9a\xfbb=:\xcdX\x81', 'image_offset': 3920},
    ]
    assert parsed_event.sender_image_path == '/System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd'
    assert parsed_event.mach_continuous_timestamp == 14148120017736
    assert parsed_event.size == 270
    assert parsed_event.sender_image_uuid == b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\'
    assert parsed_event.format_string == '%s Cannot deactivateAudioSession with %{public}@'
    assert parsed_event.type_ == 1024
    assert parsed_event.time_to_live == 14
    assert parsed_event.activity_identifier == 442
    assert parsed_event.process_image_path == '/System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd'
    assert parsed_event.log_type == OsLogType.FAULT
    assert parsed_event.process_image_uuid == b'\x94\x82\x8e\xdd`p1<\x93\x1d\xab\xa0\x18\xf0f\\'
    assert parsed_event.composed_message == (
        '-[CSFallbackAudioSessionReleaseProvider fallbackDeactivateAudioSession:'
        'error:] Cannot deactivateAudioSession with (null)'
    )
    assert parsed_event.unix_date == datetime(2021, 10, 20, 7, 23, 3, 341124, tzinfo=timezone.utc)
    assert parsed_event.sender == 'corespeechd'
    assert parsed_event.category == 'Framework'
    assert parsed_event.process_identifier == 118
    assert parsed_event.sender_image_offset == 1264156
    assert parsed_event.trace_identifier.namespace == FirehoseTracepointNamespace.log
    assert parsed_event.trace_identifier.type_ == FirehoseTracepointLogType.fault
    assert not parsed_event.trace_identifier.has_large_offset
    assert not parsed_event.trace_identifier.has_unique_pid
    assert parsed_event.trace_identifier.has_current_aid
    assert parsed_event.trace_identifier.pc_style == FirehoseTracepointFlagsPcStyle.main_exe
    assert parsed_event.trace_identifier.flags == (
            FirehoseTracepointLogFlags.has_context_data |
            FirehoseTracepointLogFlags.has_rules | FirehoseTracepointLogFlags.has_subsystem
    )
    assert parsed_event.trace_identifier.code == 1730654
    assert parsed_event.boot_uuid == b'\x08\xcc\xed\xc6g\xb8O\xe9\xa4\xf0\xa8d\xa0\xba^\x1e'
