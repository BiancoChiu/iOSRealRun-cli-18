from uuid import UUID

from pykdebugparser.kevent import Kevent
from pykdebugparser.trace_handlers.dyld import RtldFlag


def test_uuid_map_a(traces_parser):
    events = [
        Kevent(timestamp=2087564153638,
               data=(b'\x19\xdd*\xd4E\xe01\x97\xa5\xc4S\xb3W\xf3a\xa0\x000u\xaa\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(10894735564102884633, 11556785676805719205, 7154774016, 0), tid=200651, debugid=520421376,
               eventid=520421376, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].uuid == UUID('19dd2ad4-45e0-3197-a5c4-53b357f361a0')
    assert ret[0].load_addr == 0x1aa753000
    assert ret[0].fsid == 0


def test_uuid_map_b(traces_parser):
    events = [
        Kevent(timestamp=2086624121103,
               data=(b'\xe9@\x02\x00\xff\xff\xff\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1152921500312027369, 0, 0, 0), tid=200063, debugid=520421380, eventid=520421380,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].fid_objno == 147689
    assert ret[0].fid_generation == 0xfffffff


def test_uuid_shared_cache_a(traces_parser):
    events = [
        Kevent(timestamp=2086625169813,
               data=(b'\n\x01x\x91Y\xfd>"\xb8\x9e\x148K0\xb5\n\x00\x80e\x8a\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(2467688206980088074, 771576010785463992, 6616875008, 0), tid=200065, debugid=520421416,
               eventid=520421416, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].uuid == UUID('0a017891-59fd-3e22-b89e-14384b30b50a')
    assert ret[0].load_addr == 0x18a658000
    assert ret[0].fsid == 0


def test_uuid_shared_cache_b(traces_parser):
    events = [
        Kevent(timestamp=2086625169822,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=200065, debugid=520421420, eventid=520421420, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].fid_objno == 0
    assert ret[0].fid_generation == 0


def test_timing_launch_executable(traces_parser):
    events = [
        Kevent(timestamp=2375523588323,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x97\x00\x01\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 4304863232, 0, 0), tid=227140, debugid=520552453, eventid=520552452, func_qualifier=1),
        Kevent(timestamp=2087564153638,
               data=(b'\x19\xdd*\xd4E\xe01\x97\xa5\xc4S\xb3W\xf3a\xa0\x000u\xaa\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(10894735564102884633, 11556785676805719205, 7154774016, 0), tid=227140, debugid=520421376,
               eventid=520421376, func_qualifier=0),
        Kevent(timestamp=2375524298242,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 0, 0, 3), tid=227140, debugid=520552454, eventid=520552452, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[1].main_executable_mh == 0x100970000
    assert ret[1].uuid_map_a[0].uuid == UUID('19dd2ad4-45e0-3197-a5c4-53b357f361a0')
    assert ret[1].uuid_map_a[0].load_addr == 0x1aa753000


def test_timing_func_for_add_image(traces_parser):
    events = [
        Kevent(timestamp=2375525615541,
               data=(b'\xd1\x06\x00\x00\x00\x00\x00\x80\x00\xa0\xa1\xb9\x01\x00\x00\x00\xbcOD\x9c\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777553, 7409344512, 6916689852, 0), tid=227140, debugid=520552473,
               eventid=520552472, func_qualifier=1),
        Kevent(timestamp=2375525615595,
               data=(b'\xd1\x06\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777553, 0, 0, 0), tid=227140,
               debugid=520552474, eventid=520552472, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].addr == 0x1b9a1a000
    assert ret[0].func == 0x19c444fbc


def test_timing_bootstrap_start(traces_parser):
    events = [
        Kevent(timestamp=2375523577973,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 0), tid=227140, debugid=520552500, eventid=520552500, func_qualifier=0),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'DBG_DYLD_TIMING_BOOTSTRAP_START'


def test_timing_dlopen(traces_parser):
    events = [
        Kevent(timestamp=2375526922507,
               data=b'\x00\x00\x08\x1f\x00\x00\x00\x00\x0f\xda\x00\x00\x00\x00\xacp/System/Library/',
               values=(520617984, 8118864228242217487, 3417499243072017199, 3420891154821048652), tid=227157,
               debugid=117506049, eventid=117506048, func_qualifier=1),
        Kevent(timestamp=2375526922509, data=b'PrivateFrameworks/AppleFSCompres',
               values=(5072588517250003536, 7742373267996762482, 5072579785478188915, 8315178114207400787), tid=227157,
               debugid=117506048, eventid=117506048, func_qualifier=0),
        Kevent(timestamp=2375526922512, data=b'sion.framework/AppleFSCompressio',
               values=(7021787118631348595, 4697091075611256173, 8017343323464036464, 8028074750225051757), tid=227157,
               debugid=117506048, eventid=117506048, func_qualifier=0),
        Kevent(timestamp=2375526922515,
               data=(b'n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(110, 0, 0, 0), tid=227157,
               debugid=117506050, eventid=117506048,
               func_qualifier=2),
        Kevent(timestamp=2375526922532,
               data=(b'(\x08\x00\x00\x00\x00\x00\x80\x0f\xda\x00\x00\x00\x00\xacp\x00\x01\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777896, 8118864228242217487, 256, 0), tid=227157, debugid=520617985,
               eventid=520617984, func_qualifier=1),
        Kevent(timestamp=2375526922543,
               data=(b'\x00\x00\x08\x1f\x00\x00\x00\x00\x0f\xda\x00\x00\x00\x00\xacp\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(520617984, 8118864228242217487, 0, 0), tid=227157, debugid=117506051, eventid=117506048,
               func_qualifier=3),
        Kevent(timestamp=2375526922709,
               data=(b'(\x08\x00\x00\x00\x00\x00\x80\x81\xfd\xfa\r\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777896, 234552705, 0, 0), tid=227157, debugid=520617986, eventid=520617984,
               func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    dlopen = ret[-1]
    assert dlopen.path == '/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression'
    assert dlopen.flags == [RtldFlag.RTLD_FIRST]
    assert dlopen.handle == 0xdfafd81


def test_timing_dlopen_preflight(traces_parser):
    events = [
        Kevent(timestamp=2375540021590,
               data=b'\x04\x00\x08\x1f\x00\x00\x00\x00]\xdb\x00\x00\x00\x00\xacp/System/Library/',
               values=(520617988, 8118864228242217821, 3417499243072017199, 3420891154821048652), tid=227191,
               debugid=117506049, eventid=117506048, func_qualifier=1),
        Kevent(timestamp=2375540021596, data=b'Frameworks/AVFoundation.framewor',
               values=(8245940720249172550, 8462059561127211883, 3345734071897646190, 8245940720249172582), tid=227191,
               debugid=117506048, eventid=117506048, func_qualifier=0),
        Kevent(timestamp=2375540021598,
               data=b'k/AVFoundation\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
               values=(7959390264332726123, 121424789660004, 0, 0), tid=227191, debugid=117506050,
               eventid=117506048, func_qualifier=2),
        Kevent(timestamp=2375540021616,
               data=(b'\xb4\x04\x00\x00\x00\x00\x00\x80]\xdb\x00\x00\x00\x00\xacp\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777012, 8118864228242217821, 0, 0), tid=227191, debugid=520617989,
               eventid=520617988, func_qualifier=1),
        Kevent(timestamp=2375540021631,
               data=(b'\x04\x00\x08\x1f\x00\x00\x00\x00]\xdb\x00\x00\x00\x00\xacp\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(520617988, 8118864228242217821, 0, 0), tid=227191, debugid=117506051, eventid=117506048,
               func_qualifier=3),
        Kevent(timestamp=2375540021742,
               data=(b'\xb4\x04\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777012, 1, 0, 0), tid=227191, debugid=520617990, eventid=520617988,
               func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    preflight = ret[-1]
    assert preflight.path == '/System/Library/Frameworks/AVFoundation.framework/AVFoundation'
    assert preflight.compatible


def test_timing_dlclose(traces_parser):
    events = [
        Kevent(timestamp=2375542917792,
               data=(b'k\x07\x00\x00\x00\x00\x00\x80\x80O\x1d\x0e\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777707, 236801920, 0, 0), tid=227240, debugid=520617993, eventid=520617992,
               func_qualifier=1),
        Kevent(timestamp=2375542919124,
               data=(b'k\x07\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854777707, 0, 0, 0), tid=227240, debugid=520617994,
               eventid=520617992, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].handle == 0xe1d4f80


def test_timing_dlsym(traces_parser):
    events = [
        Kevent(timestamp=2375529754749,
               data=b'\x0c\x00\x08\x1f\x00\x00\x00\x00\xcc\xda\x00\x00\x00\x00\xacpUIApplicationDid',
               values=(520617996, 8118864228242217676, 7163375912484948309, 7235389517453685857), tid=227140,
               debugid=117506049, eventid=117506048, func_qualifier=1),
        Kevent(timestamp=2375529754752, data=b'EnterBackgroundNotification\x00\x00\x00\x00\x00',
               values=(7161077941591633477, 5648761283289442155, 8386093285481477231, 7237481), tid=227140,
               debugid=117506050, eventid=117506048, func_qualifier=2),
        Kevent(timestamp=2375529754762,
               data=(b'\xf3\x08\x00\x00\x00\x00\x00\x80\x80\xf0\xe0\r\x00\x00\x00\x00\xcc\xda\x00'
                     b'\x00\x00\x00\xacp\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854778099, 232845440, 8118864228242217676, 0), tid=227140, debugid=520617997,
               eventid=520617996, func_qualifier=1),
        Kevent(timestamp=2375529754772,
               data=(b'\x0c\x00\x08\x1f\x00\x00\x00\x00\xcc\xda\x00\x00\x00\x00\xacp\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(520617996, 8118864228242217676, 0, 0), tid=227140, debugid=117506051, eventid=117506048,
               func_qualifier=3),
        Kevent(timestamp=2375529754963,
               data=(b'\xf3\x08\x00\x00\x00\x00\x00\x80P!\x9e\xd9\x01\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854778099, 7945986384, 0, 0), tid=227140, debugid=520617998, eventid=520617996,
               func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    dlsym = ret[-1]
    assert dlsym.handle == 0xde0f080
    assert dlsym.symbol == 'UIApplicationDidEnterBackgroundNotification'
    assert dlsym.address == 0x1d99e2150


def test_timing_dladdr(traces_parser):
    events = [
        Kevent(timestamp=2375525034640,
               data=(b'\x86\x04\x00\x00\x00\x00\x00\x80(}\xe9\x8d\x01\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(9223372036854776966, 6675856680, 0, 0), tid=227161, debugid=520618001, eventid=520618000,
               func_qualifier=1),
        Kevent(timestamp=2375525034950,
               data=(b'\x86\x04\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00`\xe5'
                     b'\x8d\x01\x00\x00\x00\x0c|\xe9\x8d\x01\x00\x00\x00'),
               values=(9223372036854776966, 1, 6675587072, 6675856396), tid=227161,
               debugid=520618002, eventid=520618000, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert ret[0].addr == 0x18de97d28
    assert ret[0].ret == 1
