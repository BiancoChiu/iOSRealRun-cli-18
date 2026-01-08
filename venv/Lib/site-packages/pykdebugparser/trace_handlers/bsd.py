import ctypes
import enum
import errno
from dataclasses import dataclass
from functools import partial
from signal import Signals
import socket
from typing import List

IOC_REQUEST_PARAMS = {
    0x20000000: 'IOC_VOID',
    0x40000000: 'IOC_OUT',
    0x80000000: 'IOC_IN',
    0xc0000000: 'IOC_IN | IOC_OUT',
    0xe0000000: 'IOC_DIRMASK'
}


class BscOpenFlags(enum.Enum):
    O_RDONLY = 0x0000
    O_WRONLY = 0x0001
    O_RDWR = 0x0002
    O_ACCMODE = 0x0003
    O_NONBLOCK = 0x0004
    O_APPEND = 0x0008
    O_SHLOCK = 0x0010
    O_EXLOCK = 0x0020
    O_ASYNC = 0x0040
    O_NOFOLLOW = 0x0100
    O_CREAT = 0x0200
    O_TRUNC = 0x0400
    O_EXCL = 0x0800
    O_EVTONLY = 0x8000
    O_SYMLINK = 0x200000
    O_CLOEXEC = 0x1000000


S_IFMT = 0o170000


class StatFlags(enum.Flag):
    S_IXOTH = 0o1
    S_IWOTH = 0o2
    S_IROTH = 0o4
    S_IXGRP = 0o10
    S_IWGRP = 0o20
    S_IRGRP = 0o40
    S_IXUSR = 0o100
    S_IWUSR = 0o200
    S_IRUSR = 0o400
    S_ISTXT = 0o1000
    S_ISGID = 0o2000
    S_ISUID = 0o4000
    S_IFIFO = 0o10000
    S_IFCHR = 0o20000
    S_IFDIR = 0o40000
    S_IFBLK = 0o60000
    S_IFREG = 0o100000
    S_IFLNK = 0o120000
    S_IFSOCK = 0o140000


class SocketMsgFlags(enum.Enum):
    MSG_OOB = 0x1
    MSG_PEEK = 0x2
    MSG_DONTROUTE = 0x4
    MSG_EOR = 0x8
    MSG_TRUNC = 0x10
    MSG_CTRUNC = 0x20
    MSG_WAITALL = 0x40
    MSG_DONTWAIT = 0x80
    MSG_EOF = 0x100
    MSG_WAITSTREAM = 0x200
    MSG_FLUSH = 0x400
    MSG_HOLD = 0x800
    MSG_SEND = 0x1000
    MSG_HAVEMORE = 0x2000
    MSG_RCVMORE = 0x4000
    MSG_COMPAT = 0x8000
    MSG_NEEDSA = 0x10000
    MSG_NBIO = 0x20000
    MSG_SKIPCFIL = 0x40000
    MSG_USEUPCALL = 0x80000000


class BscAccessFlags(enum.Enum):
    F_OK = 0x0
    X_OK = 0x1
    W_OK = 0x2
    R_OK = 0x4


class BscChangeableFlags(enum.Enum):
    UF_NODUMP = 0x1
    UF_IMMUTABLE = 0x2
    UF_APPEND = 0x4
    UF_OPAQUE = 0x8
    UF_HIDDEN = 0x8000
    SF_ARCHIVED = 0x10000
    SF_IMMUTABLE = 0x20000
    SF_APPEND = 0x40000


class SigprocmaskFlags(enum.Enum):
    SIG_BLOCK = 1
    SIG_UNBLOCK = 2
    SIG_SETMASK = 3


class FcntlCmd(enum.Enum):
    F_DUPFD = 0
    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    F_GETOWN = 5
    F_SETOWN = 6
    F_GETLK = 7
    F_SETLK = 8
    F_SETLKW = 9
    F_SETLKWTIMEOUT = 10
    F_FLUSH_DATA = 40
    F_CHKCLEAN = 41
    F_PREALLOCATE = 42
    F_SETSIZE = 43
    F_RDADVISE = 44
    F_RDAHEAD = 45
    F_NOCACHE = 48
    F_LOG2PHYS = 49
    F_GETPATH = 50
    F_FULLFSYNC = 51
    F_PATHPKG_CHECK = 52
    F_FREEZE_FS = 53
    F_THAW_FS = 54
    F_GLOBAL_NOCACHE = 55
    F_OPENFROM = 56
    F_UNLINKFROM = 57
    F_CHECK_OPENEVT = 58
    F_ADDSIGS = 59
    F_MARKDEPENDENCY = 60
    F_ADDFILESIGS = 61
    F_NODIRECT = 62
    F_GETPROTECTIONCLASS = 63
    F_SETPROTECTIONCLASS = 64
    F_LOG2PHYS_EXT = 65
    F_GETLKPID = 66
    F_DUPFD_CLOEXEC = 67
    F_SETSTATICCONTENT = 68
    F_MOVEDATAEXTENTS = 69
    F_SETBACKINGSTORE = 70
    F_GETPATH_MTMINFO = 71
    F_GETCODEDIR = 72
    F_SETNOSIGPIPE = 73
    F_GETNOSIGPIPE = 74
    F_TRANSCODEKEY = 75
    F_SINGLE_WRITER = 76
    F_GETPROTECTIONLEVEL = 77
    F_FINDSIGS = 78
    F_GETDEFAULTPROTLEVEL = 79
    F_MAKECOMPRESSED = 80
    F_SET_GREEDY_MODE = 81
    F_SETIOTYPE = 82
    F_ADDFILESIGS_FOR_DYLD_SIM = 83
    F_RECYCLE = 84
    F_BARRIERFSYNC = 85
    F_OFD_SETLK = 90
    F_OFD_SETLKW = 91
    F_OFD_GETLK = 92
    F_OFD_SETLKWTIMEOUT = 93
    F_OFD_GETLKPID = 94
    F_SETCONFINED = 95
    F_GETCONFINED = 96
    F_ADDFILESIGS_RETURN = 97
    F_CHECK_LV = 98
    F_PUNCHHOLE = 99
    F_TRIM_ACTIVE_FILE = 100
    F_SPECULATIVE_READ = 101
    F_GETPATH_NOFIRMLINK = 102
    F_ADDFILESIGS_INFO = 103
    F_ADDFILESUPPL = 104
    F_GETSIGSINFO = 105


class PriorityWhich(enum.Enum):
    PRIO_PROCESS = 0
    PRIO_PGRP = 1
    PRIO_USER = 2
    PRIO_DARWIN_THREAD = 3
    PRIO_DARWIN_PROCESS = 4
    PRIO_DARWIN_GPU = 5
    PRIO_DARWIN_ROLE = 6
    PRIO_DARWIN_GAME_MODE = 7
    PRIO_DARWIN_CARPLAY_MODE = 8


class SocketOptionName(enum.Enum):
    SO_DEBUG = 0x1
    SO_ACCEPTCONN = 0x2
    SO_REUSEADDR = 0x4
    SO_KEEPALIVE = 0x8
    SO_DONTROUTE = 0x10
    SO_BROADCAST = 0x20
    SO_USELOOPBACK = 0x40
    SO_LINGER = 0x80
    SO_OOBINLINE = 0x100
    SO_REUSEPORT = 0x200
    SO_TIMESTAMP = 0x400
    SO_TIMESTAMP_MONOTONIC = 0x800
    SO_ACCEPTFILTER = 0x1000
    SO_SNDBUF = 0x1001
    SO_RCVBUF = 0x1002
    SO_SNDLOWAT = 0x1003
    SO_RCVLOWAT = 0x1004
    SO_SNDTIMEO = 0x1005
    SO_RCVTIMEO = 0x1006
    SO_ERROR = 0x1007
    SO_TYPE = 0x1008
    SO_LABEL = 0x1010
    SO_PEERLABEL = 0x1011
    SO_NREAD = 0x1020
    SO_NKE = 0x1021
    SO_NOSIGPIPE = 0x1022
    SO_NOADDRERR = 0x1023
    SO_NWRITE = 0x1024
    SO_REUSESHAREUID = 0x1025
    SO_NOTIFYCONFLICT = 0x1026
    SO_UPCALLCLOSEWAIT = 0x1027
    SO_LINGER_SEC = 0x1080
    SO_RESTRICTIONS = 0x1081
    SO_RANDOMPORT = 0x1082
    SO_NP_EXTENSIONS = 0x1083
    SO_EXECPATH = 0x1085
    SO_TRAFFIC_CLASS = 0x1086
    SO_RECV_TRAFFIC_CLASS = 0x1087
    SO_TRAFFIC_CLASS_DBG = 0x1088
    SO_OPTION_UNUSED_0 = 0x1089
    SO_PRIVILEGED_TRAFFIC_CLASS = 0x1090
    SO_DEFUNCTIT = 0x1091
    SO_DEFUNCTOK = 0x1100
    SO_ISDEFUNCT = 0x1101
    SO_OPPORTUNISTIC = 0x1102
    SO_FLUSH = 0x1103
    SO_RECV_ANYIF = 0x1104
    SO_TRAFFIC_MGT_BACKGROUND = 0x1105
    SO_FLOW_DIVERT_TOKEN = 0x1106
    SO_DELEGATED = 0x1107
    SO_DELEGATED_UUID = 0x1108
    SO_NECP_ATTRIBUTES = 0x1109
    SO_CFIL_SOCK_ID = 0x1110
    SO_NECP_CLIENTUUID = 0x1111
    SO_NUMRCVPKT = 0x1112
    SO_AWDL_UNRESTRICTED = 0x1113
    SO_EXTENDED_BK_IDLE = 0x1114
    SO_MARK_CELLFALLBACK = 0x1115
    SO_NET_SERVICE_TYPE = 0x1116
    SO_QOSMARKING_POLICY_OVERRIDE = 0x1117
    SO_INTCOPROC_ALLOW = 0x1118
    SO_NETSVC_MARKING_LEVEL = 0x1119
    SO_NECP_LISTENUUID = 0x1120
    SO_MPKL_SEND_INFO = 0x1122
    SO_STATISTICS_EVENT = 0x1123
    SO_WANT_KEV_SOCKET_CLOSED = 0x1124
    SO_DONTTRUNC = 0x2000
    SO_WANTMORE = 0x4000
    SO_WANTOOBFLAG = 0x8000
    SO_NOWAKEFROMSLEEP = 0x10000
    SO_NOAPNFALLBK = 0x20000
    SO_TIMESTAMP_CONTINUOUS = 0x40000


def sockopt_format_level_and_option(level, option_name):
    if level == socket.SOL_SOCKET:
        return 'SOL_SOCKET', SocketOptionName(option_name).name
    else:
        return level, option_name


class RusageWho(enum.Enum):
    RUSAGE_CHILDREN = -1
    RUSAGE_SELF = 0


class FlockOperation(enum.Enum):
    LOCK_SH = 1
    LOCK_EX = 2
    LOCK_NB = 4
    LOCK_UN = 8


class CsopsOps(enum.Enum):
    CS_OPS_STATUS = 0
    CS_OPS_MARKINVALID = 1
    CS_OPS_MARKHARD = 2
    CS_OPS_MARKKILL = 3
    CS_OPS_PIDPATH = 4
    CS_OPS_CDHASH = 5
    CS_OPS_PIDOFFSET = 6
    CS_OPS_ENTITLEMENTS_BLOB = 7
    CS_OPS_MARKRESTRICT = 8
    CS_OPS_SET_STATUS = 9
    CS_OPS_BLOB = 10
    CS_OPS_IDENTITY = 11
    CS_OPS_CLEARINSTALLER = 12
    CS_OPS_CLEARPLATFORM = 13
    CS_OPS_TEAMID = 14
    CS_OPS_CLEAR_LV = 15
    CS_OPS_16 = 16


class ProcInfoCall(enum.Enum):
    PROC_INFO_CALL_LISTPIDS = 0x1
    PROC_INFO_CALL_PIDINFO = 0x2
    PROC_INFO_CALL_PIDFDINFO = 0x3
    PROC_INFO_CALL_KERNMSGBUF = 0x4
    PROC_INFO_CALL_SETCONTROL = 0x5
    PROC_INFO_CALL_PIDFILEPORTINFO = 0x6
    PROC_INFO_CALL_TERMINATE = 0x7
    PROC_INFO_CALL_DIRTYCONTROL = 0x8
    PROC_INFO_CALL_PIDRUSAGE = 0x9
    PROC_INFO_CALL_PIDORIGINATORINFO = 0xa
    PROC_INFO_CALL_LISTCOALITIONS = 0xb
    PROC_INFO_CALL_CANUSEFGHW = 0xc
    PROC_INFO_CALL_PIDDYNKQUEUEINFO = 0xd
    PROC_INFO_CALL_UDATA_INFO = 0xe
    PROC_INFO_CALL_SET_DYLD_IMAGES = 0xf
    PROC_INFO_CALL_TERMINATE_RSR = 0x10
    PROC_INFO_CALL_SIGNAL_AUDITTOKEN = 0x11
    PROC_INFO_CALL_TERMINATE_AUDITTOKEN = 0x12
    PROC_INFO_CALL_DELEGATE_SIGNAL = 0x13
    PROC_INFO_CALL_DELEGATE_TERMINATE = 0x14


class FsSnapshotOp(enum.Enum):
    SNAPSHOT_OP_CREATE = 0x01
    SNAPSHOT_OP_DELETE = 0x02
    SNAPSHOT_OP_RENAME = 0x03
    SNAPSHOT_OP_MOUNT = 0x04
    SNAPSHOT_OP_REVERT = 0x05
    SNAPSHOT_OP_ROOT = 0x06


def serialize_open_flags(flags: int) -> List[BscOpenFlags]:
    call_flags = []
    for flag in (BscOpenFlags.O_RDWR, BscOpenFlags.O_WRONLY):
        if flags & flag.value:
            call_flags.append(flag)
            break
    else:  # No break.
        call_flags.append(BscOpenFlags.O_RDONLY)

    for flag in (
            BscOpenFlags.O_CREAT, BscOpenFlags.O_APPEND, BscOpenFlags.O_TRUNC, BscOpenFlags.O_EXCL,
            BscOpenFlags.O_NONBLOCK, BscOpenFlags.O_SHLOCK, BscOpenFlags.O_EXLOCK, BscOpenFlags.O_NOFOLLOW,
            BscOpenFlags.O_SYMLINK, BscOpenFlags.O_EVTONLY, BscOpenFlags.O_CLOEXEC):
        if flags & flag.value:
            call_flags.append(flag)
    return call_flags


def serialize_stat_flags(flags: int) -> List[StatFlags]:
    stat_flags = []
    for flag in list(StatFlags):
        if flag.value & S_IFMT:
            if flags & S_IFMT == flag.value:
                stat_flags.append(flag)
        elif flag.value & flags:
            stat_flags.append(flag)
    return stat_flags


def serialize_result(end_event, success_name='', fmt=lambda x: x) -> str:
    error_code = end_event.values[0]
    res = end_event.values[1]
    if error_code in errno.errorcode:
        err = f'errno: {errno.errorcode[error_code]}({error_code})'
    else:
        err = f'errno: {error_code}'
    success = f'{success_name}: {fmt(res)}' if success_name else ''
    return success if not error_code else err


def serialize_access_flags(flags: int) -> List[BscAccessFlags]:
    amode = [flag for flag in BscAccessFlags if flag.value & flags]
    if not amode:
        amode = [BscAccessFlags.F_OK]
    return amode


@dataclass
class BscOpen:
    ktraces: List
    path: str
    flags: List
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'''open{no_cancel}("{self.path}", {' | '.join(map(lambda f: f.name, self.flags))}), {self.result}'''


@dataclass
class BscOpenat:
    ktraces: List
    dirfd: int
    path: str
    flags: List
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return (f'''openat{no_cancel}({self.dirfd}, "{self.path}", '''
                f'''{' | '.join(map(lambda f: f.name, self.flags))}), {self.result}''')


@dataclass
class BscRead:
    ktraces: List
    fd: int
    address: int
    size: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'read{no_cancel}({self.fd}, {hex(self.address)}, {self.size}), {self.result}'


@dataclass
class BscWrite:
    ktraces: List
    fd: int
    address: int
    size: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'write{no_cancel}({self.fd}, {hex(self.address)}, {self.size}), {self.result}'


@dataclass
class BscPread:
    ktraces: List
    fd: int
    address: int
    size: int
    offset: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'pread{no_cancel}({self.fd}, {hex(self.address)}, {self.size}, {hex(self.offset)}), {self.result}'


@dataclass
class BscPwrite:
    ktraces: List
    fd: int
    address: int
    size: int
    offset: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'pwrite{no_cancel}({self.fd}, {hex(self.address)}, {self.size}, {hex(self.offset)}), {self.result}'


@dataclass
class BscSysFstat64:
    ktraces: List
    fd: int
    result: str

    def __str__(self):
        rep = f'fstat64({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscLstat64:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'lstat64("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetdirentries64:
    ktraces: List
    fd: int
    buf: int
    bufsize: int
    position: int
    result: str

    def __str__(self):
        return f'getdirentries64({self.fd}, {hex(self.buf)}, {self.bufsize}, {hex(self.position)}), {self.result}'


@dataclass
class BscStatfs64:
    ktraces: List
    path: str
    buf: int
    result: str

    def __str__(self):
        rep = f'statfs64("{self.path}", {hex(self.buf)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFstatfs64:
    ktraces: List
    fd: int
    buf: int
    result: str

    def __str__(self):
        rep = f'fstatfs64({self.fd}, {hex(self.buf)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetfsstat64:
    ktraces: List
    buf: int
    bufsize: int
    flags: int
    result: str

    def __str__(self):
        return f'getfsstat64({hex(self.buf)}, {self.bufsize}, {self.flags}), {self.result}'


@dataclass
class BscPthreadFchdir:
    ktraces: List
    fd: int
    result: str

    def __str__(self):
        rep = f'pthread_fchdir({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAudit:
    ktraces: List
    record: int
    length: int
    result: str

    def __str__(self):
        rep = f'audit({hex(self.record)}, {self.length})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAuditon:
    ktraces: List
    cmd: int
    data: int
    length: int
    result: str

    def __str__(self):
        rep = f'auditon({self.cmd}, {hex(self.data)}, {self.length})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetauid:
    ktraces: List
    auid: int
    result: str

    def __str__(self):
        rep = f'getauid({hex(self.auid)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetauid:
    ktraces: List
    auid: int
    result: str

    def __str__(self):
        rep = f'setauid({hex(self.auid)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscBsdthreadCreate:
    ktraces: List
    pid: int

    def __str__(self):
        return 'thread_create()'


@dataclass
class BscKqueue:
    ktraces: List
    result: str

    def __str__(self):
        return f'kqueue(), {self.result}'


@dataclass
class BscKevent:
    ktraces: List
    kq: int
    changelist: int
    nchanges: int
    eventlist: int
    result: str

    def __str__(self):
        return f'kevent({self.kq}, {hex(self.changelist)}, {self.nchanges}, {hex(self.eventlist)}), {self.result}'


@dataclass
class BscLchown:
    ktraces: List
    path: str
    owner: int
    group: int
    result: str

    def __str__(self):
        rep = f'lchown("{self.path}", {self.owner}, {self.group})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscBsdthreadRegister:
    ktraces: List
    threadstart: int
    wqthread: int
    pthsize: int
    dummy_value: int
    result: str

    def __str__(self):
        rep = f'thread_register({hex(self.threadstart)}, {hex(self.wqthread)}, {self.pthsize}, {hex(self.dummy_value)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscWorkqOpen:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'workq_open()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscWorkqKernreturn:
    ktraces: List
    options: int
    item: int
    affinity: int
    prio: int
    result: str

    def __str__(self):
        return f'workq_kernreturn({self.options}, {hex(self.item)}, {self.affinity}, {self.prio}), {self.result}'


@dataclass
class BscKevent64:
    ktraces: List
    kq: int
    changelist: int
    nchanges: int
    eventlist: int
    result: str

    def __str__(self):
        return f'kevent64({self.kq}, {hex(self.changelist)}, {self.nchanges}, {hex(self.eventlist)}), {self.result}'


@dataclass
class BscThreadSelfid:
    ktraces: List
    result: str

    def __str__(self):
        return f'thread_selfid(), {self.result}'


@dataclass
class BscKeventQos:
    ktraces: List
    kq: int
    changelist: int
    nchanges: int
    eventlist: int
    result: str

    def __str__(self):
        return f'kevent_qos({self.kq}, {hex(self.changelist)}, {self.nchanges}, {hex(self.eventlist)}), {self.result}'


@dataclass
class BscKeventId:
    ktraces: List
    kq: int
    changelist: int
    nchanges: int
    eventlist: int
    result: str

    def __str__(self):
        return f'kevent_id({self.kq}, {hex(self.changelist)}, {self.nchanges}, {hex(self.eventlist)}), {self.result}'


@dataclass
class BscMacSyscall:
    ktraces: List
    policy: int
    call: int
    arg: int
    result: str

    def __str__(self):
        rep = f'mac_syscall({hex(self.policy)}, {self.call}, {hex(self.arg)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPselect:
    ktraces: List
    nfds: int
    readfds: int
    writefds: int
    errorfds: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return (f'pselect{no_cancel}({self.nfds}, {hex(self.readfds)}, {hex(self.writefds)}, {hex(self.errorfds)}),'
                f' {self.result}')


@dataclass
class BscFsgetpath:
    ktraces: List
    buf: int
    bufsize: int
    fsid: int
    objid: int
    path: str
    result: str

    def __str__(self):
        rep = f'fsgetpath({hex(self.buf)}, {self.bufsize}, {hex(self.fsid)}, {self.objid}), {self.result}'
        if self.path:
            rep += f' path: "{self.path}"'
        return rep


@dataclass
class BscSysFileportMakeport:
    ktraces: List
    fd: int
    portnamep: int
    result: str

    def __str__(self):
        rep = f'fileport_makeport({self.fd}, {hex(self.portnamep)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysFileportMakefd:
    ktraces: List
    port: int
    result: str

    def __str__(self):
        return f'fileport_makefd({self.port}), {self.result}'


@dataclass
class BscAuditSessionPort:
    ktraces: List
    asid: int
    portnamep: int
    result: str

    def __str__(self):
        rep = f'audit_session_port({self.asid}, {hex(self.portnamep)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPidSuspend:
    ktraces: List
    pid: int
    result: str

    def __str__(self):
        rep = f'pid_suspend({self.pid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPidResume:
    ktraces: List
    pid: int
    result: str

    def __str__(self):
        rep = f'pid_resume({self.pid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPidHibernate:
    ktraces: List
    pid: int
    result: str

    def __str__(self):
        rep = f'pid_hibernate({self.pid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPidShutdownSockets:
    ktraces: List
    pid: int
    level: int
    result: str

    def __str__(self):
        rep = f'pid_shutdown_sockets({self.pid}, {self.level})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSharedRegionMapAndSlideNp:
    ktraces: List
    fd: int
    count: int
    mappings: int
    slide: int
    result: str

    def __str__(self):
        rep = f'shared_region_map_and_slide_np({self.fd}, {self.count}, {hex(self.mappings)}, {self.slide})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscKasInfo:
    ktraces: List
    selector: int
    value: int
    size: int
    result: str

    def __str__(self):
        rep = f'kas_info({self.selector}, {hex(self.value)}, {hex(self.size)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMemorystatusControl:
    ktraces: List
    command: int
    pid: int
    flags: int
    buffer: int
    result: str

    def __str__(self):
        rep = f'memorystatus_control({self.command}, {self.pid}, {self.flags}, {hex(self.buffer)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGuardedOpenNp:
    ktraces: List
    path: str
    guard: int
    guardflags: int
    flags: List
    result: str

    def __str__(self):
        flags = ' | '.join(map(lambda f: f.name, self.flags))
        return f'guarded_open_np("{self.path}", {hex(self.guard)}, {self.guardflags}, {flags}), {self.result}'


@dataclass
class BscGuardedCloseNp:
    ktraces: List
    fd: int
    guard: int
    result: str

    def __str__(self):
        rep = f'guarded_close_np({self.fd}, {hex(self.guard)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGuardedKqueueNp:
    ktraces: List
    guard: int
    guardflags: int
    result: str

    def __str__(self):
        rep = f'guarded_kqueue_np({hex(self.guard)}, {self.guardflags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChangeFdguardNp:
    ktraces: List
    fd: int
    guard: int
    guardflags: int
    nguard: int
    result: str

    def __str__(self):
        rep = f'change_fdguard_np({self.fd}, {hex(self.guard)}, {self.guardflags}, {hex(self.nguard)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUsrctl:
    ktraces: List
    flags: int
    result: str

    def __str__(self):
        rep = f'usrctl({self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscProcRlimitControl:
    ktraces: List
    pid: int
    flavor: int
    arg: int
    result: str

    def __str__(self):
        rep = f'proc_rlimit_control({self.pid}, {self.flavor}, {hex(self.arg)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscConnectx:
    ktraces: List
    socket: int
    endpoints: int
    associd: int
    flags: int
    result: str

    def __str__(self):
        rep = f'connectx({self.socket}, {hex(self.endpoints)}, {self.associd}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscDisconnectx:
    ktraces: List
    s: int
    aid: int
    cid: int
    result: str

    def __str__(self):
        rep = f'disconnectx({self.s}, {self.aid}, {self.cid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPeeloff:
    ktraces: List
    s: int
    aid: int
    result: str

    def __str__(self):
        rep = f'peeloff({self.s}, {self.aid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSocketDelegate:
    ktraces: List
    domain: socket.AddressFamily
    type: socket.SocketKind
    protocol: int
    epid: int
    result: str

    def __str__(self):
        return f'socket_delegate({self.domain.name}, {self.type.name}, {self.protocol}, {self.epid}), {self.result}'


@dataclass
class BscTelemetry:
    ktraces: List
    cmd: int
    deadline: int
    interval: int
    leeway: int
    result: str

    def __str__(self):
        rep = f'telemetry({self.cmd}, {self.deadline}, {self.interval}, {self.leeway})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscProcUuidPolicy:
    ktraces: List
    operation: int
    uuid: int
    uuidlen: int
    flags: int
    result: str

    def __str__(self):
        rep = f'proc_uuid_policy({self.operation}, {self.uuid}, {self.uuidlen}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMemorystatusGetLevel:
    ktraces: List
    level: int
    result: str

    def __str__(self):
        rep = f'memorystatus_get_level({hex(self.level)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSystemOverride:
    ktraces: List
    timeout: int
    flags: int
    result: str

    def __str__(self):
        rep = f'system_override({self.timeout}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscVfsPurge:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'vfs_purge()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSfiCtl:
    ktraces: List
    operation: int
    sfi_class: int
    time: int
    out_time: int
    result: str

    def __str__(self):
        rep = f'sfi_ctl({self.operation}, {self.sfi_class}, {self.time}, {hex(self.out_time)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSfiPidctl:
    ktraces: List
    operation: int
    pid: int
    sfi_flags: int
    out_sfi_flags: int
    result: str

    def __str__(self):
        rep = f'sfi_pidctl({self.operation}, {self.pid}, {self.sfi_flags}, {hex(self.out_sfi_flags)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscCoalition:
    ktraces: List
    operation: int
    cid: int
    flags: int
    result: str

    def __str__(self):
        rep = f'coalition({self.operation}, {hex(self.cid)}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscCoalitionInfo:
    ktraces: List
    flavor: int
    cid: int
    buffer: int
    bufsize: int
    result: str

    def __str__(self):
        rep = f'coalition_info({self.flavor}, {hex(self.cid)}, {hex(self.buffer)}, {hex(self.bufsize)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNecpMatchPolicy:
    ktraces: List
    parameters: int
    parameters_size: int
    returned_result: int
    result: str

    def __str__(self):
        rep = f'necp_match_policy({hex(self.parameters)}, {self.parameters_size}, {hex(self.returned_result)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetattrlistbulk:
    ktraces: List
    dirfd: int
    alist: int
    attributeBuffer: int
    bufferSize: int
    result: str

    def __str__(self):
        return (f'getattrlistbulk({self.dirfd}, {hex(self.alist)}, {hex(self.attributeBuffer)}, {self.bufferSize}),'
                f' {self.result}')


@dataclass
class BscClonefileat:
    ktraces: List
    src_dirfd: int
    src: str
    dst_dirfd: int
    dst: str
    result: str

    def __str__(self):
        rep = f'clonefileat({self.src_dirfd}, "{self.src}", {self.dst_dirfd}, "{self.dst}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscRenameat:
    ktraces: List
    fromfd: int
    from_: str
    tofd: int
    to: str
    result: str

    def __str__(self):
        rep = f'renameat({self.fromfd}, "{self.from_}", {self.tofd}, "{self.to}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFaccessat:
    ktraces: List
    fd: int
    path: str
    amode: List
    flag: int
    result: str

    def __str__(self):
        amode = ' | '.join(map(lambda f: f.name, self.amode))
        rep = f'faccessat({self.fd}, "{self.path}", {amode}, {self.flag})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchmodat:
    ktraces: List
    fd: int
    path: str
    mode: List
    flag: int
    result: str

    def __str__(self):
        mode = ' | '.join(map(lambda f: f.name, self.mode))
        rep = f'fchmodat({self.fd}, "{self.path}", {mode}, {self.flag})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchownat:
    ktraces: List
    fd: int
    path: str
    uid: int
    gid: int
    result: str

    def __str__(self):
        rep = f'fchownat({self.fd}, "{self.path}", {self.uid}, {self.gid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFstatat:
    ktraces: List
    fd: int
    path: str
    ub: int
    flag: int
    result: str

    def __str__(self):
        rep = f'fstatat({self.fd}, "{self.path}", {hex(self.ub)}, {self.flag})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFstatat64:
    ktraces: List
    fd: int
    path: str
    ub: int
    flag: int
    result: str

    def __str__(self):
        rep = f'fstatat64({self.fd}, "{self.path}", {hex(self.ub)}, {self.flag})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscLinkat:
    ktraces: List
    fd1: int
    path: str
    fd2: int
    link: str
    result: str

    def __str__(self):
        rep = f'linkat({self.fd1}, "{self.path}", {self.fd2}, "{self.link}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUnlinkat:
    ktraces: List
    fd: int
    path: str
    flag: int
    result: str

    def __str__(self):
        rep = f'unlinkat({self.fd}, "{self.path}", {self.flag})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscReadlinkat:
    ktraces: List
    fd: int
    path: str
    buf: int
    bufsize: int
    result: str

    def __str__(self):
        return f'readlinkat({self.fd}, "{self.path}", {hex(self.buf)}, {self.bufsize}), {self.result}'


@dataclass
class BscSymlinkat:
    ktraces: List
    path1: str
    fd: int
    path2: str
    result: str

    def __str__(self):
        rep = f'symlinkat("{self.path1}", {self.fd}, "{self.path2}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMkdirat:
    ktraces: List
    fd: int
    path: str
    mode: List
    result: str

    def __str__(self):
        mode = ' | '.join(map(lambda f: f.name, self.mode))
        rep = f'mkdirat({self.fd}, "{self.path}", {mode})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetattrlistat:
    ktraces: List
    fd: int
    path: str
    alist: int
    attributeBuffer: int
    result: str

    def __str__(self):
        rep = f'getattrlistat({self.fd}, "{self.path}", {hex(self.alist)}, {hex(self.attributeBuffer)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscProcTraceLog:
    ktraces: List
    pid: int
    uniqueid: int
    result: str

    def __str__(self):
        rep = f'proc_trace_log({self.pid}, {self.uniqueid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscBsdthreadCtl:
    ktraces: List
    cmd: int
    arg1: int
    arg2: int
    arg3: int
    result: str

    def __str__(self):
        rep = f'bsdthread_ctl({self.cmd}, {hex(self.arg1)}, {hex(self.arg2)}, {hex(self.arg3)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscOpenbyidNp:
    ktraces: List
    fsid: int
    objid: int
    oflags: List
    result: str

    def __str__(self):
        oflags = ' | '.join(map(lambda f: f.name, self.oflags))
        return f'openbyid_np({self.fsid}, {self.objid}, {oflags}), {self.result}'


@dataclass
class BscRecvmsgX:
    ktraces: List
    s: int
    msgp: int
    cnt: int
    flags: int
    result: str

    def __str__(self):
        return f'recvmsg_x({self.s}, {hex(self.msgp)}, {self.cnt}, {self.flags}), {self.result}'


@dataclass
class BscSendmsgX:
    ktraces: List
    s: int
    msgp: int
    cnt: int
    flags: int
    result: str

    def __str__(self):
        return f'sendmsg_x({self.s}, {hex(self.msgp)}, {self.cnt}, {self.flags}), {self.result}'


@dataclass
class BscThreadSelfusage:
    ktraces: List
    result: str

    def __str__(self):
        return f'thread_selfusage(), {self.result}'


@dataclass
class BscCsrctl:
    ktraces: List
    op: int
    useraddr: int
    usersize: int
    result: str

    def __str__(self):
        rep = f'csrctl({self.op}, {hex(self.useraddr)}, {self.usersize})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGuardedOpenDprotectedNp:
    ktraces: List
    path: str
    guard: int
    guardflags: int
    flags: List
    result: str

    def __str__(self):
        oflags = ' | '.join(map(lambda f: f.name, self.flags))
        return (f'guarded_open_dprotected_np("{self.path}", {hex(self.guard)}, {self.guardflags}, {oflags})'
                f', {self.result}')


@dataclass
class BscGuardedWriteNp:
    ktraces: List
    fd: int
    guard: int
    cbuf: int
    nbyte: int
    result: str

    def __str__(self):
        return f'guarded_write_np({self.fd}, {hex(self.guard)}, {hex(self.cbuf)}, {self.nbyte}), {self.result}'


@dataclass
class BscGuardedPwriteNp:
    ktraces: List
    fd: int
    guard: int
    buf: int
    nbyte: int
    result: str

    def __str__(self):
        return f'guarded_pwrite_np({self.fd}, {hex(self.guard)}, {hex(self.buf)}, {self.nbyte}), {self.result}'


@dataclass
class BscGuardedWritevNp:
    ktraces: List
    fd: int
    guard: int
    iovp: int
    iovcnt: int
    result: str

    def __str__(self):
        return f'guarded_writev_np({self.fd}, {hex(self.guard)}, {hex(self.iovp)}, {self.iovcnt}), {self.result}'


@dataclass
class BscRenameatxNp:
    ktraces: List
    fromfd: int
    from_: str
    tofd: int
    to: str
    result: str

    def __str__(self):
        rep = f'renameatx_np({self.fromfd}, "{self.from_}", {self.tofd}, "{self.to}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMremapEncrypted:
    ktraces: List
    addr: int
    len: int
    cryptid: int
    cputype: int
    result: str

    def __str__(self):
        rep = f'mremap_encrypted({hex(self.addr)}, {self.len}, {self.cryptid}, {self.cputype})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNetagentTrigger:
    ktraces: List
    agent_uuid: int
    agent_uuidlen: int
    result: str

    def __str__(self):
        rep = f'netagent_trigger({self.agent_uuid}, {self.agent_uuidlen})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscStackSnapshotWithConfig:
    ktraces: List
    stackshot_config_version: int
    stackshot_config: int
    stackshot_config_size: int
    result: str

    def __str__(self):
        rep = (f'stack_snapshot_with_config({self.stackshot_config_version}, {hex(self.stackshot_config)}'
               f', {self.stackshot_config_size})')
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMicrostackshot:
    ktraces: List
    tracebuf: int
    tracebuf_size: int
    flags: int
    result: str

    def __str__(self):
        return f'microstackshot({hex(self.tracebuf)}, {self.tracebuf_size}, {self.flags}), {self.result}'


@dataclass
class BscGrabPgoData:
    ktraces: List
    uuid: int
    flags: int
    buffer: int
    size: int
    result: str

    def __str__(self):
        return f'grab_pgo_data({hex(self.uuid)}, {self.flags}, {hex(self.buffer)}, {self.size}), {self.result}'


@dataclass
class BscPersona:
    ktraces: List
    operation: int
    flags: int
    buffer: int
    size: int
    result: str

    def __str__(self):
        rep = f'persona({self.operation}, {self.flags}, {hex(self.buffer)}, {hex(self.size)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMachEventlinkSignal:
    ktraces: List
    eventlink_port: int
    signal_count: int
    result: str

    def __str__(self):
        rep = f'mach_eventlink_signal({self.eventlink_port}, {self.signal_count})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMachEventlinkWaitUntil:
    ktraces: List
    eventlink_port: int
    wait_count: int
    deadline: int
    clock_id: int
    result: str

    def __str__(self):
        rep = (f'mach_eventlink_wait_until({self.eventlink_port}, {hex(self.wait_count)}, {self.deadline}'
               f', {self.clock_id})')
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMachEventlinkSignalWaitUntil:
    ktraces: List
    eventlink_port: int
    wait_count: int
    signal_count: int
    deadline: int
    result: str

    def __str__(self):
        rep = (f'mach_eventlink_signal_wait_until({self.eventlink_port}, {hex(self.wait_count)}, {self.signal_count}'
               f', {self.deadline})')
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscWorkIntervalCtl:
    ktraces: List
    operation: int
    work_interval_id: int
    arg: int
    len: int
    result: str

    def __str__(self):
        rep = f'work_interval_ctl({self.operation}, {self.work_interval_id}, {hex(self.arg)}, {self.len})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetentropy:
    ktraces: List
    buffer: int
    size: int
    result: str

    def __str__(self):
        rep = f'getentropy({hex(self.buffer)}, {self.size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNecpOpen:
    ktraces: List
    flags: int
    result: str

    def __str__(self):
        return f'necp_open({self.flags}), {self.result}'


@dataclass
class BscNecpClientAction:
    ktraces: List
    necp_fd: int
    action: int
    client_id: int
    client_id_len: int
    result: str

    def __str__(self):
        return (f'necp_client_action({self.necp_fd}, {self.action}, {hex(self.client_id)}, {self.client_id_len})'
                f', {self.result}')


@dataclass
class BscNexusOpen:
    ktraces: List
    result: str

    def __str__(self):
        return f'nexus_open(), {self.result}'


@dataclass
class BscNexusRegister:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'nexus_register()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNexusDeregister:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'nexus_deregister()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNexusCreate:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'nexus_create()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNexusDestroy:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'nexus_destroy()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNexusGetOpt:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'nexus_get_opt()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNexusSetOpt:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'nexus_set_opt()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChannelOpen:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'channel_open()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChannelGetInfo:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'channel_get_info()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChannelSync:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'channel_sync()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChannelGetOpt:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'channel_get_opt()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChannelSetOpt:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'channel_set_opt()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUlockWait:
    ktraces: List
    operation: int
    addr: int
    value: int
    timeout: int
    result: str

    def __str__(self):
        return f'ulock_wait({self.operation}, {hex(self.addr)}, {self.value}, {self.timeout}), {self.result}'


@dataclass
class BscUlockWake:
    ktraces: List
    operation: int
    addr: int
    wake_value: int
    result: str

    def __str__(self):
        return f'ulock_wake({self.operation}, {hex(self.addr)}, {self.wake_value}), {self.result}'


@dataclass
class BscFclonefileat:
    ktraces: List
    src_fd: int
    dst_dirfd: int
    dst: str
    flags: int
    result: str

    def __str__(self):
        rep = f'fclonefileat({self.src_fd}, {self.dst_dirfd}, "{self.dst}", {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFsSnapshot:
    ktraces: List
    op: FsSnapshotOp
    dirfd: int
    name1: str
    name2: str
    result: str

    def __str__(self):
        rep = f'fs_snapshot({self.op.name}, {self.dirfd}, "{self.name1}", "{self.name2}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscTerminateWithPayload:
    ktraces: List
    pid: int
    reason_namespace: int
    reason_code: int
    payload: int
    result: str

    def __str__(self):
        rep = (f'terminate_with_payload({self.pid}, {self.reason_namespace}, {hex(self.reason_code)}'
               f', {hex(self.payload)})')
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAbortWithPayload:
    ktraces: List
    reason_namespace: int
    reason_code: int
    payload: int
    payload_size: int

    def __str__(self):
        return (f'abort_with_payload({self.reason_namespace}, {hex(self.reason_code)}, {hex(self.payload)}'
                f', {self.payload_size})')


@dataclass
class BscNecpSessionOpen:
    ktraces: List
    flags: int
    result: str

    def __str__(self):
        return f'necp_session_open({self.flags}), {self.result}'


@dataclass
class BscNecpSessionAction:
    ktraces: List
    necp_fd: int
    action: int
    in_buffer: int
    in_buffer_length: int
    result: str

    def __str__(self):
        rep = f'necp_session_action({self.necp_fd}, {self.action}, {hex(self.in_buffer)}, {self.in_buffer_length})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetattrlistat:
    ktraces: List
    fd: int
    path: str
    alist: int
    attributeBuffer: int
    result: str

    def __str__(self):
        rep = f'setattrlistat({self.fd}, "{self.path}", {hex(self.alist)}, {hex(self.attributeBuffer)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNetQosGuideline:
    ktraces: List
    param: int
    param_len: int
    result: str

    def __str__(self):
        return f'net_qos_guideline({hex(self.param)}, {self.param_len}), {self.result}'


@dataclass
class BscFmount:
    ktraces: List
    type: int
    fd: int
    flags: int
    data: int
    result: str

    def __str__(self):
        rep = f'fmount({hex(self.type)}, {self.fd}, {self.flags}, {hex(self.data)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNtpAdjtime:
    ktraces: List
    tp: int
    result: str

    def __str__(self):
        return f'ntp_adjtime({hex(self.tp)}), {self.result}'


@dataclass
class BscNtpGettime:
    ktraces: List
    ntvp: int
    result: str

    def __str__(self):
        rep = f'ntp_gettime({hex(self.ntvp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscOsFaultWithPayload:
    ktraces: List
    reason_namespace: int
    reason_code: int
    payload: int
    payload_size: int
    result: str

    def __str__(self):
        rep = (f'os_fault_with_payload({self.reason_namespace}, {hex(self.reason_code)}, {hex(self.payload)}'
               f', {self.payload_size})')
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscKqueueWorkloopCtl:
    ktraces: List
    cmd: int
    options: int
    addr: int
    sz: int
    result: str

    def __str__(self):
        rep = f'kqueue_workloop_ctl({self.cmd}, {self.options}, {hex(self.addr)}, {self.sz})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMachBridgeRemoteTime:
    ktraces: List
    local_timestamp: int
    result: str

    def __str__(self):
        rep = f'mach_bridge_remote_time({self.local_timestamp})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscCoalitionLedger:
    ktraces: List
    operation: int
    cid: int
    buffer: int
    bufsize: int
    result: str

    def __str__(self):
        rep = f'coalition_ledger({self.operation}, {hex(self.cid)}, {hex(self.buffer)}, {hex(self.bufsize)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscLogData:
    ktraces: List
    tag: int
    flags: int
    buffer: int
    size: int
    result: str

    def __str__(self):
        rep = f'log_data({self.tag}, {self.flags}, {hex(self.buffer)}, {self.size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMemorystatusAvailableMemory:
    ktraces: List
    result: str

    def __str__(self):
        return f'memorystatus_available_memory(), {self.result}'


@dataclass
class BscSharedRegionMapAndSlide2Np:
    ktraces: List
    files_count: int
    shared_file_np: int
    mappings_count: int
    mappings: int
    result: str

    def __str__(self):
        rep = (f'shared_region_map_and_slide_2_np({self.files_count}, {hex(self.shared_file_np)},'
               f' {hex(self.mappings_count)}, {hex(self.mappings)})')
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPivotRoot:
    ktraces: List
    new_rootfs_path_before: str
    old_rootfs_path_after: str
    result: str

    def __str__(self):
        rep = f'pivot_root("{self.new_rootfs_path_before}", "{self.old_rootfs_path_after}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscTaskInspectForPid:
    ktraces: List
    target_tport: int
    pid: int
    t: int
    result: str

    def __str__(self):
        rep = f'task_inspect_for_pid({self.target_tport}, {self.pid}, {self.t})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscTaskReadForPid:
    ktraces: List
    target_tport: int
    pid: int
    t: int
    result: str

    def __str__(self):
        rep = f'task_read_for_pid({self.target_tport}, {self.pid}, {self.t})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysPreadv:
    ktraces: List
    fd: int
    iovp: int
    iovcnt: int
    offset: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'preadv{no_cancel}({self.fd}, {hex(self.iovp)}, {self.iovcnt}, {self.offset}), {self.result}'


@dataclass
class BscSysPwritev:
    ktraces: List
    fd: int
    iovp: int
    iovcnt: int
    offset: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'pwritev{no_cancel}({self.fd}, {hex(self.iovp)}, {self.iovcnt}, {self.offset}), {self.result}'


@dataclass
class BscUlockWait2:
    ktraces: List
    operation: int
    addr: int
    value: int
    timeout: int
    result: str

    def __str__(self):
        return f'ulock_wait2({self.operation}, {hex(self.addr)}, {self.value}, {self.timeout}), {self.result}'


@dataclass
class BscProcInfoExtendedId:
    ktraces: List
    callnum: int
    pid: int
    flavor: int
    flags: int
    result: str

    def __str__(self):
        rep = f'proc_info_extended_id({self.callnum}, {self.pid}, {self.flavor}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysClose:
    ktraces: List
    fd: str
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'close{no_cancel}({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscLink:
    ktraces: List
    oldpath: str
    newpath: str
    result: str

    def __str__(self):
        rep = f'link("{self.oldpath}", "{self.newpath}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUnlink:
    ktraces: List
    pathname: str
    result: str

    def __str__(self):
        rep = f'unlink("{self.pathname}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChdir:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'chdir("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchdir:
    ktraces: List
    fd: int
    result: str

    def __str__(self):
        rep = f'fchdir({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMknod:
    ktraces: List
    pathname: str
    mode: int
    dev: int
    result: str

    def __str__(self):
        rep = f'mknod("{self.pathname}", {self.mode}, {self.dev})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChmod:
    ktraces: List
    pathname: str
    mode: List
    result: str

    def __str__(self):
        rep = f'''chmod("{self.pathname}", {' | '.join(map(lambda f: f.name, self.mode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChown:
    ktraces: List
    pathname: str
    owner: int
    group: int
    result: str

    def __str__(self):
        rep = f'''chown("{self.pathname}", {self.owner}, {self.group})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetpid:
    ktraces: List
    pid: int

    def __str__(self):
        return f'getpid(), pid: {self.pid}'


@dataclass
class BscSetuid:
    ktraces: List
    uid: int
    result: str

    def __str__(self):
        rep = f'setuid({self.uid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetuid:
    ktraces: List
    uid: int

    def __str__(self):
        return f'getuid(), uid: {self.uid}'


@dataclass
class BscGeteuid:
    ktraces: List
    uid: int

    def __str__(self):
        return f'geteuid(), uid: {self.uid}'


@dataclass
class BscWait4:
    ktraces: List
    pid: int
    status: int
    options: int
    rusage: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'wait4{no_cancel}({self.pid}, {hex(self.status)}, {self.options}, {hex(self.rusage)}), {self.result}'


@dataclass
class BscRecvmsg:
    ktraces: List
    socket: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'recvmsg{no_cancel}({self.socket}), {self.result}'


@dataclass
class BscSendmsg:
    ktraces: List
    socket: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'sendmsg{no_cancel}({self.socket}), {self.result}'


@dataclass
class BscRecvfrom:
    ktraces: List
    socket: int
    buffer: int
    length: int
    flags: List
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return (f'''recvfrom{no_cancel}({self.socket}, {hex(self.buffer)}, {self.length}, '''
                f'''{' | '.join(map(lambda f: f.name, self.flags)) if self.flags else '0'}), {self.result}''')


@dataclass
class BscAccept:
    ktraces: List
    socket: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'accept{no_cancel}({self.socket}), {self.result}'


@dataclass
class BscGetpeername:
    ktraces: List
    socket: int
    address: int
    address_len: int
    result: str

    def __str__(self):
        rep = f'getpeername({self.socket}, {hex(self.address)}, {hex(self.address_len)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetsockname:
    ktraces: List
    socket: int
    address: int
    address_len: int
    result: str

    def __str__(self):
        rep = f'getsockname({self.socket}, {hex(self.address)}, {hex(self.address_len)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAccess:
    ktraces: List
    path: str
    amode: List
    result: str

    def __str__(self):
        rep = f'''access("{self.path}", {' | '.join(map(lambda f: f.name, self.amode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscChflags:
    ktraces: List
    path: str
    flags: List
    result: str

    def __str__(self):
        rep = f'''chflags("{self.path}", {' | '.join(map(lambda f: f.name, self.flags))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchflags:
    ktraces: List
    fd: int
    flags: List
    result: str

    def __str__(self):
        rep = f'''fchflags({self.fd}, {' | '.join(map(lambda f: f.name, self.flags))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSync:
    ktraces: List

    def __str__(self):
        return 'sync()'


@dataclass
class BscKill:
    ktraces: List
    pid: int
    sig: int
    result: str

    def __str__(self):
        rep = f'kill({self.pid}, {self.sig})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetppid:
    ktraces: List
    pid: int

    def __str__(self):
        return f'getppid(), pid: {self.pid}'


@dataclass
class BscSysDup:
    ktraces: List
    fildes: int
    result: str

    def __str__(self):
        return f'dup({self.fildes}), {self.result}'


@dataclass
class BscPipe:
    ktraces: List
    result: str

    def __str__(self):
        return f'pipe(), {self.result}'


@dataclass
class BscGetegid:
    ktraces: List
    gid: int

    def __str__(self):
        return f'getegid(), gid: {self.gid}'


@dataclass
class BscSigaction:
    ktraces: List
    sig: Signals
    act: int
    oact: int
    result: str

    def __str__(self):
        rep = f'sigaction({self.sig.name}, {hex(self.act)}, {hex(self.oact)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetgid:
    ktraces: List
    gid: int

    def __str__(self):
        return f'getgid(), gid: {self.gid}'


@dataclass
class BscSigprocmap:
    ktraces: List
    how: SigprocmaskFlags
    set: int
    oset: int
    result: str

    def __str__(self):
        rep = f'sigprocmask({self.how.name}, {hex(self.set)}, {hex(self.oset)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetlogin:
    ktraces: List
    address: int

    def __str__(self):
        return f'getlogin(), address: {hex(self.address)}'


@dataclass
class BscSetlogin:
    ktraces: List
    address: int
    result: str

    def __str__(self):
        rep = f'setlogin({hex(self.address)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAcct:
    ktraces: List
    file: str
    result: str

    def __str__(self):
        rep = f'acct("{self.file}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSigpending:
    ktraces: List
    set: int
    result: str

    def __str__(self):
        rep = f'sigpending({hex(self.set)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSigaltstack:
    ktraces: List
    ss_address: int
    oss_address: int
    result: str

    def __str__(self):
        rep = f'sigaltstack({hex(self.ss_address)}, {hex(self.oss_address)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscIoctl:
    ktraces: List
    fildes: int
    request: int
    arg: int
    result: str

    def __str__(self):
        params = IOC_REQUEST_PARAMS[self.request & 0xf0000000]
        group = chr((self.request >> 8) & 0xff)
        number = self.request & 0xff
        length = (self.request >> 16) & 0x1fff
        ioc = f'''_IOC({params}, '{group}', {number}, {length})'''
        rep = f'ioctl({self.fildes}, {hex(self.request)} /* {ioc} */, {hex(self.arg)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscReboot:
    ktraces: List
    howto: int
    result: str

    def __str__(self):
        rep = f'reboot({self.howto})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscRevoke:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'revoke("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSymlink:
    ktraces: List
    vnode1: int
    path2: str
    result: str

    def __str__(self):
        rep = f'symlink({self.vnode1}, "{self.path2}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscReadlink:
    ktraces: List
    path: str
    buf: int
    bufsize: int
    result: str

    def __str__(self):
        return f'readlink("{self.path}", {hex(self.buf)}, {self.bufsize}), {self.result}'


@dataclass
class BscExecve:
    ktraces: List

    def __str__(self):
        return 'execve()'


@dataclass
class BscUmask:
    ktraces: List
    cmask: int
    prev_mask: int

    def __str__(self):
        return f'umask({self.cmask}), previous mask: {self.prev_mask}'


@dataclass
class BscChroot:
    ktraces: List
    dirname: str
    result: str

    def __str__(self):
        rep = f'chroot("{self.dirname}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMsync:
    ktraces: List
    addr: int
    len_: int
    flags: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'msync{no_cancel}({hex(self.addr)}, {self.len_}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscVfork:
    ktraces: List

    def __str__(self):
        return 'vfork()'


@dataclass
class BscMunmap:
    ktraces: List
    addr: int
    len_: int
    result: str

    def __str__(self):
        rep = f'munmap({hex(self.addr)}, {self.len_})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMprotect:
    ktraces: List
    addr: int
    len_: int
    prot: int
    result: str

    def __str__(self):
        rep = f'mprotect({hex(self.addr)}, {self.len_}, {self.prot})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMadvise:
    ktraces: List
    addr: int
    len_: int
    advice: int
    result: str

    def __str__(self):
        rep = f'madvise({hex(self.addr)}, {self.len_}, {self.advice})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMincore:
    ktraces: List
    addr: int
    len_: int
    vec: int
    result: str

    def __str__(self):
        rep = f'mincore({hex(self.addr)}, {self.len_}, {hex(self.vec)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetgroups:
    ktraces: List
    gidsetsize: int
    grouplist: int
    result: str

    def __str__(self):
        return f'getgroups({self.gidsetsize}, {hex(self.grouplist)}), {self.result}'


@dataclass
class BscSetgroups:
    ktraces: List
    ngroups: int
    gidset: int
    result: str

    def __str__(self):
        rep = f'setgroups({self.ngroups}, {hex(self.gidset)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetpgrp:
    ktraces: List
    pgid: int

    def __str__(self):
        return f'getpgrp(), pgid: {self.pgid}'


@dataclass
class BscSetpgid:
    ktraces: List
    pid: int
    pgid: int
    result: str

    def __str__(self):
        rep = f'setpgid({self.pid}, {self.pgid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetitimer:
    ktraces: List
    which: int
    value: int
    ovalue: int
    result: str

    def __str__(self):
        rep = f'setitimer({self.which}, {hex(self.value)}, {hex(self.ovalue)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSwapon:
    ktraces: List
    path: int
    swapflags: int
    result: str

    def __str__(self):
        rep = f'swapon({self.path}, {self.swapflags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetitimer:
    ktraces: List
    which: int
    value: int
    result: str

    def __str__(self):
        rep = f'getitimer({self.which}, {hex(self.value)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysGetdtablesize:
    ktraces: List
    table_size: int

    def __str__(self):
        return f'getdtablesize(), size: {self.table_size}'


@dataclass
class BscSysDup2:
    ktraces: List
    fildes: int
    fildes2: int
    result: str

    def __str__(self):
        rep = f'dup2({self.fildes}, {self.fildes2})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysFcntl:
    ktraces: List
    fildes: int
    cmd: FcntlCmd
    buf: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'fcntl{no_cancel}({self.fildes}, {self.cmd.name}, {hex(self.buf)}), {self.result}'


@dataclass
class BscSelect:
    ktraces: List
    nfds: int
    readfds: int
    writefds: int
    errorfds: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return (f'select{no_cancel}({self.nfds}, {hex(self.readfds)}, {hex(self.writefds)}, {hex(self.errorfds)}),'
                f' {self.result}')


@dataclass
class BscFsync:
    ktraces: List
    fildes: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'fsync{no_cancel}({self.fildes})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetpriority:
    ktraces: List
    which: PriorityWhich
    who: int
    prio: int
    result: str

    def __str__(self):
        rep = f'setpriority({self.which.name}, {self.who}, {self.prio})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSocket:
    ktraces: List
    domain: socket.AddressFamily
    type: socket.SocketKind
    protocol: int
    result: str

    def __str__(self):
        return f'socket({self.domain.name}, {self.type.name}, {self.protocol}), {self.result}'


@dataclass
class BscConnect:
    ktraces: List
    socket: int
    address: int
    address_len: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'connect{no_cancel}({self.socket}, {hex(self.address)}, {self.address_len})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetpriority:
    ktraces: List
    which: PriorityWhich
    who: int
    result: str

    def __str__(self):
        return f'getpriority({self.which.name}, {self.who}), {self.result}'


@dataclass
class BscBind:
    ktraces: List
    socket: int
    address: int
    address_len: int
    result: str

    def __str__(self):
        rep = f'bind({self.socket}, {hex(self.address)}, {self.address_len})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetsockopt:
    ktraces: List
    socket: int
    level: int
    option_name: int
    option_value: int
    result: str

    def __str__(self):
        level, option = sockopt_format_level_and_option(self.level, self.option_name)
        rep = f'setsockopt({self.socket}, {level}, {option}, {hex(self.option_value)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscListen:
    ktraces: List
    socket: int
    backlog: int
    result: str

    def __str__(self):
        rep = f'listen({self.socket}, {self.backlog})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSigsuspend:
    ktraces: List
    sigmask: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'sigsuspend{no_cancel}({hex(self.sigmask)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGettimeofday:
    ktraces: List
    tv: int
    tz: int
    result: str

    def __str__(self):
        rep = f'gettimeofday({hex(self.tv)}, {hex(self.tz)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetrusage:
    ktraces: List
    who: RusageWho
    r_usage: int
    result: str

    def __str__(self):
        rep = f'getrusage({self.who.name}, {self.r_usage})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetsockopt:
    ktraces: List
    socket: int
    level: int
    option_name: int
    option_value: int
    result: str

    def __str__(self):
        level, option = sockopt_format_level_and_option(self.level, self.option_name)
        rep = f'getsockopt({self.socket}, {level}, {option}, {hex(self.option_value)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscReadv:
    ktraces: List
    d: int
    iov: int
    iovcnt: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'readv{no_cancel}({self.d}, {hex(self.iov)}, {self.iovcnt}), {self.result}'


@dataclass
class BscWritev:
    ktraces: List
    fildes: int
    iov: int
    iovcnt: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'writev{no_cancel}({self.fildes}, {hex(self.iov)}, {self.iovcnt}), {self.result}'


@dataclass
class BscSettimeofday:
    ktraces: List
    tp: int
    tzp: int
    result: str

    def __str__(self):
        rep = f'settimeofday({hex(self.tp)}, {hex(self.tzp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchown:
    ktraces: List
    fildes: int
    owner: int
    group: int
    result: str

    def __str__(self):
        rep = f'fchown({self.fildes}, {self.owner}, {self.group})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFchmod:
    ktraces: List
    fildes: str
    mode: List
    result: str

    def __str__(self):
        rep = f'''fchmod({self.fildes}, {' | '.join(map(lambda f: f.name, self.mode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetreuid:
    ktraces: List
    ruid: int
    euid: int
    result: str

    def __str__(self):
        rep = f'setreuid({self.ruid}, {self.euid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetregid:
    ktraces: List
    rgid: int
    egid: int
    result: str

    def __str__(self):
        rep = f'setregid({self.rgid}, {self.egid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscRename:
    ktraces: List
    old: str
    new: str
    result: str

    def __str__(self):
        rep = f'rename("{self.old}", "{self.new}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysFlock:
    ktraces: List
    fd: int
    operation: List
    result: str

    def __str__(self):
        rep = f'''flock({self.fd}, {' | '.join(map(lambda o: o.name, self.operation))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMkfifo:
    ktraces: List
    path: str
    mode: List
    result: str

    def __str__(self):
        rep = f'''mkfifo("{self.path}", {' | '.join(map(lambda f: f.name, self.mode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSendto:
    ktraces: List
    socket: int
    buffer: int
    length: int
    flags: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'sendto{no_cancel}({self.socket}, {hex(self.buffer)}, {self.length}, {self.flags}), {self.result}'


@dataclass
class BscShutdown:
    ktraces: List
    socket: int
    how: int
    result: str

    def __str__(self):
        rep = f'shutdown({self.socket}, {self.how})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSocketpair:
    ktraces: List
    domain: socket.AddressFamily
    type: socket.SocketKind
    protocol: int
    socket_vector: int
    result: str

    def __str__(self):
        rep = f'socketpair({self.domain.name}, {self.type.name}, {self.protocol}, {hex(self.socket_vector)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMkdir:
    ktraces: List
    path: str
    mode: List
    result: str

    def __str__(self):
        rep = f'''mkdir("{self.path}", {' | '.join(map(lambda f: f.name, self.mode))})'''
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscRmdir:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'rmdir("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUtimes:
    ktraces: List
    path: str
    times: int
    result: str

    def __str__(self):
        rep = f'utimes("{self.path}", {hex(self.times)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFutimes:
    ktraces: List
    fildes: int
    times: int
    result: str

    def __str__(self):
        rep = f'futimes({self.fildes}, {hex(self.times)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAdjtime:
    ktraces: List
    delta: int
    olddelta: int
    result: str

    def __str__(self):
        rep = f'adjtime({hex(self.delta)}, {hex(self.olddelta)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGethostuuid:
    ktraces: List
    uuid: int
    timeout: int
    result: str

    def __str__(self):
        rep = f'gethostuuid({hex(self.uuid)}, {hex(self.timeout)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscObsKillpg:
    ktraces: List
    pgrp: int
    sig: int
    result: str

    def __str__(self):
        rep = f'killpg({self.pgrp}, {self.sig})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetsid:
    ktraces: List
    result: str

    def __str__(self):
        return f'setsid(), {self.result}'


@dataclass
class BscGetpgid:
    ktraces: List
    pid: int
    result: str

    def __str__(self):
        return f'getpgid({self.pid}), {self.result}'


@dataclass
class BscSetprivexec:
    ktraces: List
    flag: int
    result: str

    def __str__(self):
        return f'setprivexec({self.flag}), {self.result}'


@dataclass
class BscNfssvc:
    ktraces: List
    flags: int
    argstructp: int
    result: str

    def __str__(self):
        rep = f'nfssvc({self.flags}, {hex(self.argstructp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscStatfs:
    ktraces: List
    path: str
    buf: int
    result: str

    def __str__(self):
        rep = f'statfs("{self.path}", {hex(self.buf)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFstatfs:
    ktraces: List
    fd: int
    buf: int
    result: str

    def __str__(self):
        rep = f'fstatfs({self.fd}, {hex(self.buf)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUnmount:
    ktraces: List
    dir: str
    flags: int
    result: str

    def __str__(self):
        rep = f'unmount("{self.dir}", {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetfh:
    ktraces: List
    path: str
    fhp: int
    result: str

    def __str__(self):
        rep = f'getfh("{self.path}", {hex(self.fhp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscQuotactl:
    ktraces: List
    path: str
    cmd: int
    id: int
    addr: int
    result: str

    def __str__(self):
        rep = f'quotactl("{self.path}", {self.cmd}, {self.id}, {hex(self.addr)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMount:
    ktraces: List
    source: str
    dest: str
    flags: int
    data: int
    result: str

    def __str__(self):
        rep = f'mount("{self.source}", "{self.dest}", {self.flags}, {hex(self.data)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscCsops:
    ktraces: List
    pid: int
    ops: CsopsOps
    useraddr: int
    usersize: int
    result: str

    def __str__(self):
        rep = f'csops({self.pid}, {self.ops.name}, {hex(self.useraddr)}, {self.usersize})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscCsopsAudittoken:
    ktraces: List
    pid: int
    ops: CsopsOps
    useraddr: int
    usersize: int
    result: str

    def __str__(self):
        rep = f'csops_audittoken({self.pid}, {self.ops.name}, {hex(self.useraddr)}, {self.usersize})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscWaitid:
    ktraces: List
    idtype: int
    id: int
    infop: int
    options: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'waitid{no_cancel}({self.idtype}, {self.id}, {hex(self.infop)}, {self.options})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscKdebugTypefilter:
    ktraces: List
    addr: int
    size: int
    result: str

    def __str__(self):
        rep = f'kdebug_typefilter({hex(self.addr)}, {hex(self.size)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetgid:
    ktraces: List
    gid: int
    result: str

    def __str__(self):
        rep = f'setgid({self.gid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetegid:
    ktraces: List
    egid: int
    result: str

    def __str__(self):
        rep = f'setegid({self.egid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSeteuid:
    ktraces: List
    euid: int
    result: str

    def __str__(self):
        rep = f'seteuid({self.euid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscThreadSelfcounts:
    ktraces: List
    type: int
    buf: int
    nbytes: int
    result: str

    def __str__(self):
        rep = f'thread_selfcounts({self.type}, {hex(self.buf)}, {self.nbytes})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFdatasync:
    ktraces: List
    fd: int
    result: str

    def __str__(self):
        rep = f'fdatasync({self.fd})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPathconf:
    ktraces: List
    path: str
    name: int
    result: str

    def __str__(self):
        return f'pathconf("{self.path}", {self.name}), {self.result}'


@dataclass
class BscSysFpathconf:
    ktraces: List
    fildes: int
    name: int
    result: str

    def __str__(self):
        return f'fpathconf({self.fildes}, {self.name}), {self.result}'


@dataclass
class BscGetrlimit:
    ktraces: List
    resource: int
    rlp: int
    result: str

    def __str__(self):
        rep = f'getrlimit({self.resource}, {hex(self.rlp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetrlimit:
    ktraces: List
    resource: int
    rlp: int
    result: str

    def __str__(self):
        rep = f'setrlimit({self.resource}, {hex(self.rlp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetdirentries:
    ktraces: List
    fd: int
    buf: int
    nbytes: int
    basep: int
    result: str

    def __str__(self):
        return f'getdirentries({self.fd}, {hex(self.buf)}, {self.nbytes}, {hex(self.basep)}), {self.result}'


@dataclass
class BscMmap:
    ktraces: List
    addr: int
    len: int
    prot: int
    flags: int
    result: str

    def __str__(self):
        return f'mmap({hex(self.addr)}, {self.len}, {self.prot}, {self.flags}), {self.result}'


@dataclass
class BscLseek:
    ktraces: List
    fildes: int
    offset: int
    whence: int
    result: str

    def __str__(self):
        return f'lseek({self.fildes}, {self.offset}, {self.whence}), {self.result}'


@dataclass
class BscTruncate:
    ktraces: List
    path: str
    length: int
    result: str

    def __str__(self):
        rep = f'truncate("{self.path}", {self.length})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFtruncate:
    ktraces: List
    fildes: int
    length: int
    result: str

    def __str__(self):
        rep = f'ftruncate({self.fildes}, {self.length})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysctl:
    ktraces: List
    name: int
    namelen: int
    oldp: int
    oldlenp: int
    result: str

    def __str__(self):
        rep = f'sysctl({hex(self.name)}, {self.namelen}, {hex(self.oldp)}, {hex(self.oldlenp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMlock:
    ktraces: List
    addr: int
    len: int
    result: str

    def __str__(self):
        rep = f'mlock({hex(self.addr)}, {self.len})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMunlock:
    ktraces: List
    addr: int
    len: int
    result: str

    def __str__(self):
        rep = f'munlock({hex(self.addr)}, {self.len})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscUndelete:
    ktraces: List
    path: str
    result: str

    def __str__(self):
        rep = f'undelete("{self.path}")'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscOpenDprotectedNp:
    ktraces: List
    path: str
    flags: List
    class_: str
    dpflags: str
    result: str

    def __str__(self):
        flags = ' | '.join(map(lambda f: f.name, self.flags))
        return f'open_dprotected_np("{self.path}", {flags}, {self.class_}, {self.dpflags}), {self.result}'


@dataclass
class BscGetattrlist:
    ktraces: List
    path: str
    attr_list: int
    attr_buf: int
    attr_buf_size: int
    result: str

    def __str__(self):
        rep = f'getattrlist("{self.path}", {hex(self.attr_list)}, {hex(self.attr_buf)}, {self.attr_buf_size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSetattrlist:
    ktraces: List
    path: str
    attr_list: int
    attr_buf: int
    attr_buf_size: int
    result: str

    def __str__(self):
        rep = f'setattrlist("{self.path}", {hex(self.attr_list)}, {hex(self.attr_buf)}, {self.attr_buf_size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetdirentriesattr:
    ktraces: List
    fd: str
    attr_list: int
    attr_buf: int
    attr_buf_size: int
    result: str

    def __str__(self):
        return (f'getdirentriesattr({self.fd}, {hex(self.attr_list)}, {hex(self.attr_buf)}, {self.attr_buf_size})'
                f', {self.result}')


@dataclass
class BscExchangedata:
    ktraces: List
    path1: str
    path2: str
    options: int
    result: str

    def __str__(self):
        rep = f'exchangedata("{self.path1}", "{self.path2}", {self.options})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSearchfs:
    ktraces: List
    path: str
    search_block: int
    num_matches: int
    script_code: int
    result: str

    def __str__(self):
        rep = f'searchfs("{self.path}", {hex(self.search_block)}, {hex(self.num_matches)}, {self.script_code})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFgetattrlist:
    ktraces: List
    fd: int
    attr_list: int
    attr_buf: int
    attr_buf_size: int
    result: str

    def __str__(self):
        rep = f'fgetattrlist({self.fd}, {hex(self.attr_list)}, {hex(self.attr_buf)}, {self.attr_buf_size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFsetattrlist:
    ktraces: List
    fd: int
    attr_list: int
    attr_buf: int
    attr_buf_size: int
    result: str

    def __str__(self):
        rep = f'fsetattrlist({self.fd}, {hex(self.attr_list)}, {hex(self.attr_buf)}, {self.attr_buf_size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPoll:
    ktraces: List
    fds: int
    nfds: int
    timeout: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'poll{no_cancel}({hex(self.fds)}, {self.nfds}, {self.timeout}), {self.result}'


@dataclass
class BscGetxattr:
    ktraces: List
    path: str
    name: int
    value: int
    size: int
    result: str

    def __str__(self):
        return f'getxattr("{self.path}", {hex(self.name)}, {hex(self.value)}, {self.size}), {self.result}'


@dataclass
class BscFgetxattr:
    ktraces: List
    fd: int
    name: int
    value: int
    size: int
    result: str

    def __str__(self):
        return f'fgetxattr({self.fd}, {hex(self.name)}, {hex(self.value)}, {self.size}), {self.result}'


@dataclass
class BscSetxattr:
    ktraces: List
    path: str
    name: int
    value: int
    size: int
    result: str

    def __str__(self):
        rep = f'setxattr("{self.path}", {hex(self.name)}, {hex(self.value)}, {self.size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFsetxattr:
    ktraces: List
    fd: int
    name: int
    value: int
    size: int
    result: str

    def __str__(self):
        rep = f'fsetxattr({self.fd}, {hex(self.name)}, {hex(self.value)}, {self.size})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscRemovexattr:
    ktraces: List
    path: str
    name: int
    options: int
    result: str

    def __str__(self):
        rep = f'removexattr("{self.path}", {hex(self.name)}, {self.options})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFremovexattr:
    ktraces: List
    fd: int
    name: int
    options: int
    result: str

    def __str__(self):
        rep = f'fremovexattr({self.fd}, {hex(self.name)}, {self.options})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscListxattr:
    ktraces: List
    path: str
    namebuf: int
    size: int
    options: int
    result: str

    def __str__(self):
        return f'listxattr("{self.path}", {hex(self.namebuf)}, {self.size}, {self.options}), {self.result}'


@dataclass
class BscFlistxattr:
    ktraces: List
    fd: int
    namebuf: int
    size: int
    options: int
    result: str

    def __str__(self):
        return f'flistxattr({self.fd}, {hex(self.namebuf)}, {self.size}, {self.options}), {self.result}'


@dataclass
class BscFsctl:
    ktraces: List
    path: str
    request: int
    data: int
    options: int
    result: str

    def __str__(self):
        rep = f'fsctl("{self.path}", {self.request}, {hex(self.data)}, {self.options})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscInitgroups:
    ktraces: List
    name: int
    basegid: int
    result: str

    def __str__(self):
        rep = f'initgroups({hex(self.name)}, {self.basegid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPosixSpawn:
    ktraces: List
    pid: int
    path: str
    file_actions: int
    attrp: int
    stdin: str
    stdout: str
    stderr: str
    result: str

    def __str__(self):
        rep = f'posix_spawn({hex(self.pid)}, "{self.path}", {hex(self.file_actions)}, {hex(self.attrp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFfsctl:
    ktraces: List
    fd: int
    request: int
    data: int
    options: int
    result: str

    def __str__(self):
        rep = f'ffsctl({self.fd}, {self.request}, {hex(self.data)}, {self.options})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscNfsclnt:
    ktraces: List
    flags: int
    argstructp: int
    result: str

    def __str__(self):
        rep = f'nfsclnt({self.flags}, {hex(self.argstructp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscFhopen:
    ktraces: List
    fhp: int
    flags: int
    result: str

    def __str__(self):
        rep = f'fhopen({hex(self.fhp)}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMinherit:
    ktraces: List
    addr: int
    len: int
    inherit: int
    result: str

    def __str__(self):
        rep = f'minherit({hex(self.addr)}, {self.len}, {self.inherit})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemsys:
    ktraces: List
    which: int
    a2: int
    a3: int
    a4: int
    result: str

    def __str__(self):
        rep = f'semsys({self.which}, {self.a2}, {self.a3}, {self.a4})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMsgsys:
    ktraces: List
    which: int
    a2: int
    a3: int
    a4: int
    result: str

    def __str__(self):
        rep = f'msgsys({self.which}, {self.a2}, {self.a3}, {self.a4})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscShmsys:
    ktraces: List
    which: int
    a2: int
    a3: int
    a4: int
    result: str

    def __str__(self):
        rep = f'shmsys({self.which}, {self.a2}, {self.a3}, {self.a4})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemctl:
    ktraces: List
    semid: int
    semnum: int
    cmd: int
    semun: int
    result: str

    def __str__(self):
        return f'semctl({self.semid}, {self.semnum}, {self.cmd}, {hex(self.semun)}), {self.result}'


@dataclass
class BscSemget:
    ktraces: List
    key: int
    nsems: int
    semflg: int
    result: str

    def __str__(self):
        return f'semget({self.key}, {self.nsems}, {self.semflg}), {self.result}'


@dataclass
class BscSemop:
    ktraces: List
    semid: int
    sops: int
    nsops: int
    result: str

    def __str__(self):
        rep = f'semop({self.semid}, {hex(self.sops)}, {self.nsops})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMsgctl:
    ktraces: List
    msqid: int
    cmd: int
    ds: int
    result: str

    def __str__(self):
        return f'msgctl({self.msqid}, {self.cmd}, {self.ds}), {self.result}'


@dataclass
class BscMsgget:
    ktraces: List
    key: int
    msgflg: int
    result: str

    def __str__(self):
        return f'msgget({self.key}, {self.msgflg}), {self.result}'


@dataclass
class BscMsgsnd:
    ktraces: List
    msqid: int
    msgp: int
    msgsz: int
    msgflg: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'msgsnd{no_cancel}({self.msqid}, {hex(self.msgp)}, {self.msgsz}, {self.msgflg}), {self.result}'


@dataclass
class BscMsgrcv:
    ktraces: List
    msqid: int
    msgp: int
    msgsz: int
    msgtyp: int
    result: str
    no_cancel: bool

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        return f'msgrcv{no_cancel}({self.msqid}, {hex(self.msgp)}, {self.msgsz}, {self.msgtyp}), {self.result}'


@dataclass
class BscShmat:
    ktraces: List
    shmid: int
    shmaddr: int
    shmflg: int
    result: str

    def __str__(self):
        return f'shmat({self.shmid}, {hex(self.shmaddr)}, {self.shmflg}), {self.result}'


@dataclass
class BscShmctl:
    ktraces: List
    shmid: int
    cmd: int
    buf: int
    result: str

    def __str__(self):
        rep = f'shmctl({self.shmid}, {self.cmd}, {hex(self.buf)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscShmdt:
    ktraces: List
    shmaddr: int
    result: str

    def __str__(self):
        rep = f'shmdt({hex(self.shmaddr)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscShmget:
    ktraces: List
    key: int
    size: int
    shmflg: int
    result: str

    def __str__(self):
        return f'shmget({self.key}, {self.size}, {self.shmflg}), {self.result}'


@dataclass
class BscShmOpen:
    ktraces: List
    name: int
    oflag: List
    mode: List
    result: str

    def __str__(self):
        oflags = ' | '.join(map(lambda f: f.name, self.oflag))
        mode = (', ' + ' | '.join(map(lambda f: f.name, self.mode))) if BscOpenFlags.O_CREAT in self.oflag else ''
        return f'shm_open({hex(self.name)}, {oflags}{mode}), {self.result}'


@dataclass
class BscShmUnlink:
    ktraces: List
    name: int
    result: str

    def __str__(self):
        rep = f'shm_unlink({hex(self.name)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemOpen:
    ktraces: List
    name: int
    oflag: List
    mode: List
    result: str

    def __str__(self):
        oflags = ' | '.join(map(lambda f: f.name, self.oflag))
        mode = (', ' + ' | '.join(map(lambda f: f.name, self.mode))) if BscOpenFlags.O_CREAT in self.oflag else ''
        return f'sem_open({hex(self.name)}, {oflags}{mode}), {self.result}'


@dataclass
class BscSemClose:
    ktraces: List
    sem: int
    result: str

    def __str__(self):
        rep = f'sem_close({self.sem})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemUnlink:
    ktraces: List
    name: int
    result: str

    def __str__(self):
        rep = f'sem_unlink({hex(self.name)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemWait:
    ktraces: List
    sem: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'sem_wait{no_cancel}({hex(self.sem)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemTrywait:
    ktraces: List
    sem: int
    result: str

    def __str__(self):
        rep = f'sem_trywait({hex(self.sem)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemPost:
    ktraces: List
    sem: int
    result: str

    def __str__(self):
        rep = f'sem_post({hex(self.sem)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSysctlbyname:
    ktraces: List
    name: int
    oldp: int
    oldlenp: int
    newp: int
    result: str

    def __str__(self):
        rep = f'sysctlbyname({hex(self.name)}, {hex(self.oldp)}, {hex(self.oldlenp)}, {hex(self.newp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscAccessExtended:
    ktraces: List
    entries: int
    size: int
    results: int
    uid: int
    result: str

    def __str__(self):
        rep = f'access_extended({hex(self.entries)}, {self.size}, {hex(self.results)}, {self.uid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGettid:
    ktraces: List
    uidp: int
    gidp: int
    result: str

    def __str__(self):
        rep = f'gettid({hex(self.uidp)}, {hex(self.gidp)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSharedRegionCheckNp:
    ktraces: List
    startaddress: int
    result: str

    def __str__(self):
        rep = f'shared_region_check_np({hex(self.startaddress)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPsynchMutexwait:
    ktraces: List
    mutex: int
    mgen: int
    ugen: int
    tid: int
    result: str

    def __str__(self):
        rep = f'psynch_mutexwait({hex(self.mutex)}, {self.mgen}, {self.ugen}, {self.tid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPsynchMutexdrop:
    ktraces: List
    mutex: int
    mgen: int
    ugen: int
    tid: int
    result: str

    def __str__(self):
        rep = f'psynch_mutexdrop({hex(self.mutex)}, {self.mgen}, {self.ugen}, {self.tid})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPsynchCvbroad:
    ktraces: List
    cv: int
    cvlsgen: int
    cvudgen: int
    flags: int
    result: str

    def __str__(self):
        rep = f'psynch_cvbroad({hex(self.cv)}, {self.cvlsgen}, {self.cvudgen}, {self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPsynchCvsignal:
    ktraces: List
    cv: int
    cvlsgen: int
    cvugen: int
    thread_port: int
    result: str

    def __str__(self):
        rep = f'psynch_cvsignal({hex(self.cv)}, {self.cvlsgen}, {self.cvugen}, {self.thread_port})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscPsynchCvwait:
    ktraces: List
    cv: int
    cvlsgen: int
    cvugen: int
    mutex: int
    result: str

    def __str__(self):
        rep = f'psynch_cvwait({hex(self.cv)}, {self.cvlsgen}, {self.cvugen}, {hex(self.mutex)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscGetsid:
    ktraces: List
    pid: int
    result: str

    def __str__(self):
        return f'getsid({self.pid}), {self.result}'


@dataclass
class BscPsynchCvclrprepost:
    ktraces: List
    cv: int
    cvgen: int
    cvugen: int
    cvsgen: int
    result: str

    def __str__(self):
        rep = f'psynch_cvclrprepost({hex(self.cv)}, {self.cvgen}, {self.cvugen}, {self.cvsgen})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscIopolicysys:
    ktraces: List
    cmd: int
    arg: int
    result: str

    def __str__(self):
        return f'iopolicysys({self.cmd}, {hex(self.arg)}), {self.result}'


@dataclass
class BscProcessPolicy:
    ktraces: List
    scope: int
    action: int
    policy: int
    policy_subtype: int
    result: str

    def __str__(self):
        rep = f'process_policy({self.scope}, {self.action}, {self.policy}, {self.policy_subtype})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMlockall:
    ktraces: List
    flags: int
    result: str

    def __str__(self):
        rep = f'mlockall({self.flags})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscMunlockall:
    ktraces: List
    result: str

    def __str__(self):
        rep = 'munlockall()'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscIssetugid:
    ktraces: List
    result: str

    def __str__(self):
        return f'issetugid(), {self.result}'


@dataclass
class BscPthreadSigmask:
    ktraces: List
    how: int
    set: int
    oset: int
    result: str

    def __str__(self):
        rep = f'pthread_sigmask({self.how}, {hex(self.set)}, {hex(self.oset)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscDisableThreadsignal:
    ktraces: List
    value: int
    result: str

    def __str__(self):
        rep = f'disable_threadsignal({self.value})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSemwaitSignal:
    ktraces: List
    cond_sem: int
    mutex_sem: int
    timeout: int
    relative: int
    result: str
    no_cancel: bool = False

    def __str__(self):
        no_cancel = '_nocancel' if self.no_cancel else ''
        rep = f'semwait_signal{no_cancel}({self.cond_sem}, {self.mutex_sem}, {self.timeout}, {self.relative})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscProcInfo:
    ktraces: List
    callnum: ProcInfoCall
    pid: int
    flags: int
    ext_id: int
    result: str

    def __str__(self):
        rep = f'proc_info({self.callnum.name}, {self.pid}, {self.flags}, {self.ext_id})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscSendfile:
    ktraces: List
    fd: int
    s: int
    offset: int
    len: int
    result: str

    def __str__(self):
        rep = f'sendfile({self.fd}, {self.s}, {self.offset}, {hex(self.len)})'
        if self.result:
            rep += f', {self.result}'
        return rep


@dataclass
class BscStat64:
    ktraces: List
    path: str
    buf: int
    result: str

    def __str__(self):
        rep = f'stat64("{self.path}", {hex(self.buf)})'
        if self.result:
            rep += f', {self.result}'
        return rep


def handle_read(parser, events, no_cancel=False):
    result = serialize_result(events[-1], 'count')
    args = events[0].values
    return BscRead(events, args[0], args[1], args[2], result, no_cancel)


def handle_write(parser, events, no_cancel=False):
    result = serialize_result(events[-1], 'count')
    args = events[0].values
    return BscWrite(events, args[0], args[1], args[2], result, no_cancel)


def handle_open(parser, events, no_cancel=False):
    vnode = parser.parse_vnode(events)
    call_flags = serialize_open_flags(events[0].values[1])
    return BscOpen(events, vnode.path, call_flags, serialize_result(events[-1], 'fd'), no_cancel)


def handle_sys_close(parser, events, no_cancel=False):
    return BscSysClose(events, events[0].values[0], serialize_result(events[-1]), no_cancel)


def handle_link(parser, events):
    old_vnode = parser.parse_vnode(events)
    new_vnode = parser.parse_vnode([e for e in events if e not in old_vnode.ktraces])
    return BscLink(events, old_vnode.path, new_vnode.path, serialize_result(events[-1]))


def handle_unlink(parser, events):
    vnode = parser.parse_vnode(events)
    return BscUnlink(events, vnode.path, serialize_result(events[-1]))


def handle_chdir(parser, events):
    vnode = parser.parse_vnode(events)
    return BscChdir(events, vnode.path, serialize_result(events[-1]))


def handle_fchdir(parser, events):
    return BscFchdir(events, events[0].values[0], serialize_result(events[-1]))


def handle_mknod(parser, events):
    vnode = parser.parse_vnode(events)
    return BscMknod(events, vnode.path, events[0].values[1], events[0].values[2], serialize_result(events[-1]))


def handle_chmod(parser, events):
    vnode = parser.parse_vnode(events)
    return BscChmod(events, vnode.path, serialize_stat_flags(events[0].values[1]), serialize_result(events[-1]))


def handle_chown(parser, events):
    vnode = parser.parse_vnode(events)
    return BscChown(events, vnode.path, events[0].values[1], events[0].values[2], serialize_result(events[-1]))


def handle_getpid(parser, events):
    return BscGetpid(events, events[-1].values[1])


def handle_setuid(parser, events):
    return BscSetuid(events, events[0].values[0], serialize_result(events[-1]))


def handle_getuid(parser, events):
    return BscGetuid(events, events[-1].values[1])


def handle_geteuid(parser, events):
    return BscGeteuid(events, events[-1].values[1])


def handle_wait4(parser, events, no_cancel=False):
    args = events[0].values
    return BscWait4(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'pid'), no_cancel)


def handle_recvmsg(parser, events, no_cancel=False):
    return BscRecvmsg(events, events[0].values[0], serialize_result(events[-1], 'count'), no_cancel)


def handle_sendmsg(parser, events, no_cancel=False):
    return BscSendmsg(events, events[0].values[0], serialize_result(events[-1], 'count'), no_cancel)


def handle_recvfrom(parser, events, no_cancel=False):
    args = events[0].values
    flags = [flag for flag in SocketMsgFlags if flag.value & args[3]]
    return BscRecvfrom(events, args[0], args[1], args[2], flags, serialize_result(events[-1], 'count'), no_cancel)


def handle_accept(parser, events, no_cancel=False):
    return BscAccept(events, events[0].values[0], serialize_result(events[-1], 'fd'), no_cancel)


def handle_getpeername(parser, events):
    args = events[0].values
    return BscGetpeername(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_getsockname(parser, events):
    args = events[0].values
    return BscGetsockname(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_access(parser, events):
    vnode = parser.parse_vnode(events)
    amode = serialize_access_flags(events[0].values[1])
    return BscAccess(events, vnode.path, amode, serialize_result(events[-1]))


def handle_chflags(parser, events):
    vnode = parser.parse_vnode(events)
    flags = [flag for flag in BscChangeableFlags if flag.value & events[0].values[1]]
    return BscChflags(events, vnode.path, flags, serialize_result(events[-1]))


def handle_fchflags(parser, events):
    flags = [flag for flag in BscChangeableFlags if flag.value & events[0].values[1]]
    return BscFchflags(events, events[0].values[0], flags, serialize_result(events[-1]))


def handle_sync(parser, events):
    return BscSync(events)


def handle_kill(parser, events):
    return BscKill(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))


def handle_getppid(parser, events):
    return BscGetppid(events, events[-1].values[1])


def handle_sys_dup(parser, events):
    return BscSysDup(events, events[0].values[0], serialize_result(events[-1], 'fd'))


def handle_pipe(parser, events):
    error_code = events[-1].values[0]
    if error_code:
        if error_code in errno.errorcode:
            result = f'errno: {errno.errorcode[error_code]}({error_code})'
        else:
            result = f'errno: {error_code}'
    else:
        result = f'read_fd: {events[-1].values[1]}, write_fd: {events[-1].values[2]}'
    return BscPipe(events, result)


def handle_getegid(parser, events):
    return BscGetegid(events, events[-1].values[1])


def handle_sigaction(parser, events):
    args = events[0].values
    return BscSigaction(events, Signals(args[0]), args[1], args[2], serialize_result(events[-1]))


def handle_getgid(parser, events):
    return BscGetgid(events, events[-1].values[1])


def handle_sigprocmask(parser, events):
    args = events[0].values
    return BscSigprocmap(events, SigprocmaskFlags(args[0]), args[1], args[2], serialize_result(events[-1]))


def handle_getlogin(parser, events):
    return BscGetlogin(events, events[0].values[0])


def handle_setlogin(parser, events):
    return BscSetlogin(events, events[0].values[0], serialize_result(events[-1]))


def handle_acct(parser, events):
    return BscAcct(events, parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_sigpending(parser, events):
    return BscSigpending(events, events[0].values[0], serialize_result(events[-1]))


def handle_sigaltstack(parser, events):
    return BscSigaltstack(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))


def handle_ioctl(parser, events):
    args = events[0].values
    return BscIoctl(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_reboot(parser, events):
    return BscReboot(events, events[0].values[0], serialize_result(events[-1]))


def handle_revoke(parser, events):
    return BscRevoke(events, parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_symlink(parser, events):
    return BscSymlink(events, events[0].values[0], parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_readlink(parser, events):
    args = events[0].values
    return BscReadlink(events, parser.parse_vnode(events).path, args[1], args[2],
                       serialize_result(events[-1], 'count'))


def handle_execve(parser, events):
    return BscExecve(events)


def handle_umask(parser, events):
    return BscUmask(events, events[0].values[0], events[-1].values[1])


def handle_chroot(parser, events):
    return BscChroot(events, parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_msync(parser, events, no_cancel=False):
    args = events[0].values
    return BscMsync(events, args[0], args[1], args[2], serialize_result(events[-1]), no_cancel)


def handle_vfork(parser, events):
    return BscVfork(events)


def handle_munmap(parser, events):
    args = events[0].values
    return BscMunmap(events, args[0], args[1], serialize_result(events[-1]))


def handle_mprotect(parser, events):
    args = events[0].values
    return BscMprotect(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_madvise(parser, events):
    args = events[0].values
    return BscMadvise(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_mincore(parser, events):
    args = events[0].values
    return BscMincore(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_getgroups(parser, events):
    args = events[0].values
    return BscGetgroups(events, args[0], args[1], serialize_result(events[-1], 'count'))


def handle_setgroups(parser, events):
    args = events[0].values
    return BscSetgroups(events, args[0], args[1], serialize_result(events[-1]))


def handle_getpgrp(parser, events):
    return BscGetpgrp(events, events[-1].values[1])


def handle_setpgid(parser, events):
    return BscSetpgid(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))


def handle_setitimer(parser, events):
    args = events[0].values
    return BscSetitimer(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_swapon(parser, events):
    args = events[0].values
    return BscSwapon(events, args[0], args[1], serialize_result(events[-1]))


def handle_getitimer(parser, events):
    args = events[0].values
    return BscGetitimer(events, args[0], args[1], serialize_result(events[-1]))


def handle_sys_getdtablesize(parser, events):
    return BscSysGetdtablesize(events, events[-1].values[1])


def handle_sys_dup2(parser, events):
    args = events[0].values
    return BscSysDup2(events, args[0], args[1], serialize_result(events[-1]))


def handle_sys_fcntl(parser, events, no_cancel=False):
    args = events[0].values
    return BscSysFcntl(events, args[0], FcntlCmd(args[1]), args[2], serialize_result(events[-1], 'return'),
                       no_cancel)


def handle_select(parser, events, no_cancel=False):
    args = events[0].values
    return BscSelect(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'), no_cancel)


def handle_fsync(parser, events, no_cancel=False):
    return BscFsync(events, events[0].values[0], serialize_result(events[-1]), no_cancel)


def handle_setpriority(parser, events):
    args = events[0].values
    return BscSetpriority(events, PriorityWhich(args[0]), args[1], args[2], serialize_result(events[-1]))


def handle_socket(parser, events):
    args = events[0].values
    return BscSocket(events, socket.AddressFamily(args[0]), socket.SocketKind(args[1]), args[2],
                     serialize_result(events[-1], 'fd'))


def handle_connect(parser, events, no_cancel=False):
    args = events[0].values
    return BscConnect(events, args[0], args[1], args[2], serialize_result(events[-1]), no_cancel)


def handle_getpriority(parser, events):
    args = events[0].values
    return BscGetpriority(events, PriorityWhich(args[0]), args[1], serialize_result(events[-1], 'priority'))


def handle_bind(parser, events):
    args = events[0].values
    return BscBind(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_setsockopt(parser, events):
    args = events[0].values
    return BscSetsockopt(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_listen(parser, events):
    args = events[0].values
    return BscListen(events, args[0], args[1], serialize_result(events[-1]))


def handle_sigsuspend(parser, events, no_cancel=False):
    return BscSigsuspend(events, events[0].values[0], serialize_result(events[-1]), no_cancel)


def handle_gettimeofday(parser, events):
    args = events[0].values
    return BscGettimeofday(events, args[0], args[1], serialize_result(events[-1]))


def handle_getrusage(parser, events):
    args = events[0].values
    return BscGetrusage(events, RusageWho(ctypes.c_int32(args[0]).value), args[1], serialize_result(events[-1]))


def handle_getsockopt(parser, events):
    args = events[0].values
    return BscGetsockopt(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_readv(parser, events, no_cancel=False):
    args = events[0].values
    return BscReadv(events, args[0], args[1], args[2], serialize_result(events[-1], 'count'), no_cancel)


def handle_writev(parser, events, no_cancel=False):
    args = events[0].values
    return BscWritev(events, args[0], args[1], args[2], serialize_result(events[-1], 'count'), no_cancel)


def handle_settimeofday(parser, events):
    args = events[0].values
    return BscSettimeofday(events, args[0], args[1], serialize_result(events[-1]))


def handle_fchown(parser, events):
    args = events[0].values
    return BscFchown(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_fchmod(parser, events):
    args = events[0].values
    return BscFchmod(events, args[0], serialize_stat_flags(args[1]), serialize_result(events[-1]))


def handle_setreuid(parser, events):
    args = events[0].values
    return BscSetreuid(events, args[0], args[1], serialize_result(events[-1]))


def handle_setregid(parser, events):
    args = events[0].values
    return BscSetregid(events, args[0], args[1], serialize_result(events[-1]))


def handle_rename(parser, events):
    old_vnode = parser.parse_vnode(events)
    new_vnode = parser.parse_vnode([e for e in events if e not in old_vnode.ktraces])
    return BscRename(events, old_vnode.path, new_vnode.path, serialize_result(events[-1]))


def handle_sys_flock(parser, events):
    args = events[0].values
    operations = [op for op in list(FlockOperation) if args[1] & op.value]
    return BscSysFlock(events, args[0], operations, serialize_result(events[-1]))


def handle_mkfifo(parser, events):
    args = events[0].values
    return BscMkfifo(events, parser.parse_vnode(events).path, serialize_stat_flags(args[1]),
                     serialize_result(events[-1]))


def handle_sendto(parser, events, no_cancel=False):
    args = events[0].values
    return BscSendto(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'), no_cancel)


def handle_shutdown(parser, events):
    args = events[0].values
    return BscShutdown(events, args[0], args[1], serialize_result(events[-1]))


def handle_socketpair(parser, events):
    args = events[0].values
    return BscSocketpair(events, socket.AddressFamily(args[0]), socket.SocketKind(args[1]), args[2], args[3],
                         serialize_result(events[-1]))


def handle_mkdir(parser, events):
    args = events[0].values
    return BscMkdir(events, parser.parse_vnode(events).path, serialize_stat_flags(args[1]),
                    serialize_result(events[-1]))


def handle_rmdir(parser, events):
    return BscRmdir(events, parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_utimes(parser, events):
    args = events[0].values
    return BscUtimes(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1]))


def handle_futimes(parser, events):
    args = events[0].values
    return BscFutimes(events, args[0], args[1], serialize_result(events[-1]))


def handle_adjtime(parser, events):
    args = events[0].values
    return BscAdjtime(events, args[0], args[1], serialize_result(events[-1]))


def handle_gethostuuid(parser, events):
    args = events[0].values
    return BscGethostuuid(events, args[0], args[1], serialize_result(events[-1]))


def handle_obs_killpg(parser, events):
    return BscObsKillpg(events, events[0].values[0], events[0].values[1], serialize_result(events[-1]))


def handle_setsid(parser, events):
    return BscSetsid(events, serialize_result(events[-1], 'gid'))


def handle_getpgid(parser, events):
    return BscGetpgid(events, events[0].values[0], serialize_result(events[-1], 'gid'))


def handle_setprivexec(parser, events):
    return BscSetprivexec(events, events[0].values[0], serialize_result(events[-1], 'previous'))


def handle_pread(parser, events, no_cancel=False):
    result = serialize_result(events[-1], 'count')
    args = events[0].values
    return BscPread(events, args[0], args[1], args[2], args[3], result, no_cancel)


def handle_pwrite(parser, events, no_cancel=False):
    result = serialize_result(events[-1], 'count')
    args = events[0].values
    return BscPwrite(events, args[0], args[1], args[2], args[3], result, no_cancel)


def handle_nfssvc(parser, events):
    args = events[0].values
    return BscNfssvc(events, args[0], args[1], serialize_result(events[-1]))


def handle_statfs(parser, events):
    args = events[0].values
    return BscStatfs(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1]))


def handle_fstatfs(parser, events):
    args = events[0].values
    return BscFstatfs(events, args[0], args[1], serialize_result(events[-1]))


def handle_unmount(parser, events):
    args = events[0].values
    return BscUnmount(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1]))


def handle_getfh(parser, events):
    args = events[0].values
    return BscGetfh(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1]))


def handle_quotactl(parser, events):
    args = events[0].values
    return BscQuotactl(events, parser.parse_vnode(events).path, args[1], args[2], args[3],
                       serialize_result(events[-1]))


def handle_mount(parser, events):
    src_vnode = parser.parse_vnode(events)
    dst_vnode = parser.parse_vnode([e for e in events if e not in src_vnode.ktraces])
    args = events[0].values
    return BscMount(events, src_vnode.path, dst_vnode.path, args[2], args[3], serialize_result(events[-1]))


def handle_csops(parser, events):
    args = events[0].values
    return BscCsops(events, args[0], CsopsOps(args[1]), args[2], args[3], serialize_result(events[-1]))


def handle_csops_audittoken(parser, events):
    args = events[0].values
    return BscCsopsAudittoken(events, args[0], CsopsOps(args[1]), args[2], args[3], serialize_result(events[-1]))


def handle_waitid(parser, events, no_cancel=False):
    args = events[0].values
    return BscWaitid(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]), no_cancel)


def handle_kdebug_typefilter(parser, events):
    args = events[0].values
    return BscKdebugTypefilter(events, args[0], args[1], serialize_result(events[-1]))


def handle_setgid(parser, events):
    args = events[0].values
    return BscSetgid(events, args[0], serialize_result(events[-1]))


def handle_setegid(parser, events):
    args = events[0].values
    return BscSetegid(events, args[0], serialize_result(events[-1]))


def handle_seteuid(parser, events):
    args = events[0].values
    return BscSeteuid(events, args[0], serialize_result(events[-1]))


def handle_thread_selfcounts(parser, events):
    args = events[0].values
    return BscThreadSelfcounts(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_fdatasync(parser, events):
    args = events[0].values
    return BscFdatasync(events, args[0], serialize_result(events[-1]))


def handle_pathconf(parser, events):
    args = events[0].values
    return BscPathconf(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1], 'return'))


def handle_sys_fpathconf(parser, events):
    args = events[0].values
    return BscSysFpathconf(events, args[0], args[1], serialize_result(events[-1], 'return'))


def handle_getrlimit(parser, events):
    args = events[0].values
    return BscGetrlimit(events, args[0], args[1], serialize_result(events[-1]))


def handle_setrlimit(parser, events):
    args = events[0].values
    return BscSetrlimit(events, args[0], args[1], serialize_result(events[-1]))


def handle_getdirentries(parser, events):
    args = events[0].values
    return BscGetdirentries(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_mmap(parser, events):
    args = events[0].values
    return BscMmap(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count', hex))


def handle_lseek(parser, events):
    args = events[0].values
    return BscLseek(events, args[0], ctypes.c_int64(args[1]).value, args[2],
                    serialize_result(events[-1], 'count', lambda x: ctypes.c_int64(x).value))


def handle_truncate(parser, events):
    args = events[0].values
    return BscTruncate(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1]))


def handle_ftruncate(parser, events):
    args = events[0].values
    return BscFtruncate(events, args[0], args[1], serialize_result(events[-1]))


def handle_sysctl(parser, events):
    args = events[0].values
    return BscSysctl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_mlock(parser, events):
    args = events[0].values
    return BscMlock(events, args[0], args[1], serialize_result(events[-1]))


def handle_munlock(parser, events):
    args = events[0].values
    return BscMunlock(events, args[0], args[1], serialize_result(events[-1]))


def handle_undelete(parser, events):
    return BscUndelete(events, parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_open_dprotected_np(parser, events):
    args = events[0].values
    return BscOpenDprotectedNp(events, parser.parse_vnode(events).path, serialize_open_flags(args[1]), args[2],
                               args[3], serialize_result(events[-1], 'fd'))


def handle_getattrlist(parser, events):
    args = events[0].values
    return BscGetattrlist(events, parser.parse_vnode(events).path, args[1], args[2], args[3],
                          serialize_result(events[-1]))


def handle_setattrlist(parser, events):
    args = events[0].values
    return BscSetattrlist(events, parser.parse_vnode(events).path, args[1], args[2], args[3],
                          serialize_result(events[-1]))


def handle_getdirentriesattr(parser, events):
    args = events[0].values
    return BscGetdirentriesattr(events, args[0], args[1], args[2], args[3],
                                serialize_result(events[-1], 'last entry'))


def handle_exchangedata(parser, events):
    vnode1 = parser.parse_vnode(events)
    vnode2 = parser.parse_vnode([e for e in events if e not in vnode1.ktraces])
    args = events[0].values
    return BscExchangedata(events, vnode1.path, vnode2.path, args[2], serialize_result(events[-1]))


def handle_searchfs(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscSearchfs(events, vnode.path, args[1], args[2], args[3], serialize_result(events[-1]))


def handle_fgetattrlist(parser, events):
    args = events[0].values
    return BscFgetattrlist(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_fsetattrlist(parser, events):
    args = events[0].values
    return BscFsetattrlist(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_poll(parser, events, no_cancel=False):
    args = events[0].values
    return BscPoll(events, args[0], args[1], args[2], serialize_result(events[-1], 'count'), no_cancel)


def handle_getxattr(parser, events):
    args = events[0].values
    return BscGetxattr(events, parser.parse_vnode(events).path, args[1], args[2], args[3],
                       serialize_result(events[-1], 'count'))


def handle_fgetxattr(parser, events):
    args = events[0].values
    return BscFgetxattr(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_setxattr(parser, events):
    args = events[0].values
    return BscSetxattr(events, parser.parse_vnode(events).path, args[1], args[2], args[3],
                       serialize_result(events[-1]))


def handle_fsetxattr(parser, events):
    args = events[0].values
    return BscFsetxattr(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_removexattr(parser, events):
    args = events[0].values
    return BscRemovexattr(events, parser.parse_vnode(events).path, args[1], args[2], serialize_result(events[-1]))


def handle_fremovexattr(parser, events):
    args = events[0].values
    return BscFremovexattr(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_listxattr(parser, events):
    args = events[0].values
    return BscListxattr(events, parser.parse_vnode(events).path, args[1], args[2], args[3],
                        serialize_result(events[-1], 'count'))


def handle_flistxattr(parser, events):
    args = events[0].values
    return BscFlistxattr(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_fsctl(parser, events):
    args = events[0].values
    return BscFsctl(events, parser.parse_vnode(events).path, args[1], args[2], args[3], serialize_result(events[-1]))


def handle_initgroups(parser, events):
    args = events[0].values
    return BscInitgroups(events, args[0], args[1], serialize_result(events[-1]))


def handle_posix_spawn(parser, events):
    vnodes = parser.parse_vnodes(events)
    if len(vnodes) >= 6:
        stdin, stdout, stderr = vnodes[0].path, vnodes[1].path, vnodes[2].path
        path = vnodes[3].path
    else:
        stdin, stdout, stderr = None, None, None
        path = vnodes[0].path
    args = events[0].values
    return BscPosixSpawn(events, args[0], path, args[2], args[3], stdin, stdout, stderr,
                         serialize_result(events[-1]))


def handle_ffsctl(parser, events):
    args = events[0].values
    return BscFfsctl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_nfsclnt(parser, events):
    args = events[0].values
    return BscNfsclnt(events, args[0], args[1], serialize_result(events[-1]))


def handle_fhopen(parser, events):
    args = events[0].values
    return BscFhopen(events, args[0], args[1], serialize_result(events[-1]))


def handle_minherit(parser, events):
    args = events[0].values
    return BscMinherit(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_semsys(parser, events):
    args = events[0].values
    return BscSemsys(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_msgsys(parser, events):
    args = events[0].values
    return BscMsgsys(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_shmsys(parser, events):
    args = events[0].values
    return BscShmsys(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_semctl(parser, events):
    args = events[0].values
    return BscSemctl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'return'))


def handle_semget(parser, events):
    args = events[0].values
    return BscSemget(events, args[0], args[1], args[2], serialize_result(events[-1], 'id'))


def handle_semop(parser, events):
    args = events[0].values
    return BscSemop(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_msgctl(parser, events):
    args = events[0].values
    return BscMsgctl(events, args[0], args[1], args[2], serialize_result(events[-1], 'return'))


def handle_msgget(parser, events):
    args = events[0].values
    return BscMsgget(events, args[0], args[1], serialize_result(events[-1], 'id'))


def handle_msgsnd(parser, events, no_cancel=False):
    args = events[0].values
    return BscMsgsnd(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'), no_cancel)


def handle_msgrcv(parser, events, no_cancel=False):
    args = events[0].values
    return BscMsgrcv(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'), no_cancel)


def handle_shmat(parser, events):
    args = events[0].values
    return BscShmat(events, args[0], args[1], args[2], serialize_result(events[-1], 'address'))


def handle_shmctl(parser, events):
    args = events[0].values
    return BscShmctl(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_shmdt(parser, events):
    args = events[0].values
    return BscShmdt(events, args[0], serialize_result(events[-1]))


def handle_shmget(parser, events):
    args = events[0].values
    return BscShmget(events, args[0], args[1], args[2], serialize_result(events[-1], 'id'))


def handle_shm_open(parser, events):
    args = events[0].values
    oflags = serialize_open_flags(args[1])
    sflags = serialize_stat_flags(args[2]) if BscOpenFlags.O_CREAT in oflags else []
    return BscShmOpen(events, args[0], oflags, sflags, serialize_result(events[-1], 'fd'))


def handle_shm_unlink(parser, events):
    return BscShmUnlink(events, events[0].values[0], serialize_result(events[-1]))


def handle_sem_open(parser, events):
    args = events[0].values
    oflags = serialize_open_flags(args[1])
    sflags = serialize_stat_flags(args[2]) if BscOpenFlags.O_CREAT in oflags else []
    return BscSemOpen(events, args[0], oflags, sflags, serialize_result(events[-1], 'fd'))


def handle_sem_close(parser, events):
    args = events[0].values
    return BscSemClose(events, args[0], serialize_result(events[-1]))


def handle_sem_unlink(parser, events):
    args = events[0].values
    return BscSemUnlink(events, args[0], serialize_result(events[-1]))


def handle_sem_wait(parser, events, no_cancel=False):
    args = events[0].values
    return BscSemWait(events, args[0], serialize_result(events[-1]), no_cancel)


def handle_sem_trywait(parser, events):
    args = events[0].values
    return BscSemTrywait(events, args[0], serialize_result(events[-1]))


def handle_sem_post(parser, events):
    args = events[0].values
    return BscSemPost(events, args[0], serialize_result(events[-1]))


def handle_sys_sysctlbyname(parser, events):
    args = events[0].values
    return BscSysctlbyname(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_access_extended(parser, events):
    args = events[0].values
    return BscAccessExtended(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_gettid(parser, events):
    args = events[0].values
    return BscGettid(events, args[0], args[1], serialize_result(events[-1]))


def handle_shared_region_check_np(parser, events):
    args = events[0].values
    return BscSharedRegionCheckNp(events, args[0], serialize_result(events[-1]))


def handle_psynch_mutexwait(parser, events):
    args = events[0].values
    return BscPsynchMutexwait(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_psynch_mutexdrop(parser, events):
    args = events[0].values
    return BscPsynchMutexdrop(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_psynch_cvbroad(parser, events):
    args = events[0].values
    return BscPsynchCvbroad(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_psynch_cvsignal(parser, events):
    args = events[0].values
    return BscPsynchCvsignal(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_psynch_cvwait(parser, events):
    args = events[0].values
    return BscPsynchCvwait(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_getsid(parser, events):
    args = events[0].values
    return BscGetsid(events, args[0], serialize_result(events[-1], 'sid'))


def handle_psynch_cvclrprepost(parser, events):
    args = events[0].values
    return BscPsynchCvclrprepost(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_iopolicysys(parser, events):
    args = events[0].values
    return BscIopolicysys(events, args[0], args[1], serialize_result(events[-1], 'return'))


def handle_process_policy(parser, events):
    args = events[0].values
    return BscProcessPolicy(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_mlockall(parser, events):
    return BscMlockall(events, events[0].values[0], serialize_result(events[-1]))


def handle_munlockall(parser, events):
    return BscMunlockall(events, serialize_result(events[-1]))


def handle_issetugid(parser, events):
    return BscIssetugid(events, serialize_result(events[-1], 'return', bool))


def handle_pthread_sigmask(parser, events):
    args = events[0].values
    return BscPthreadSigmask(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_disable_threadsignal(parser, events):
    return BscDisableThreadsignal(events, events[0].values[0], serialize_result(events[-1]))


def handle_semwait_signal(parser, events, no_cancel=False):
    args = events[0].values
    return BscSemwaitSignal(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]), no_cancel)


def handle_proc_info(parser, events):
    args = events[0].values
    return BscProcInfo(events, ProcInfoCall(args[0]), args[1], args[2], args[3], serialize_result(events[-1]))


def handle_sendfile(parser, events):
    args = events[0].values
    return BscSendfile(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_stat64(parser, events):
    return BscStat64(events, parser.parse_vnode(events).path, events[0].values[1], serialize_result(events[-1]))


def handle_sys_fstat64(parser, events):
    return BscSysFstat64(events, events[0].values[0], serialize_result(events[-1]))


def handle_lstat64(parser, events):
    return BscLstat64(events, parser.parse_vnode(events).path, serialize_result(events[-1]))


def handle_getdirentries64(parser, events):
    args = events[0].values
    return BscGetdirentries64(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_statfs64(parser, events):
    args = events[0].values
    return BscStatfs64(events, parser.parse_vnode(events).path, args[1], serialize_result(events[-1]))


def handle_fstatfs64(parser, events):
    args = events[0].values
    return BscFstatfs64(events, args[0], args[1], serialize_result(events[-1]))


def handle_getfsstat64(parser, events):
    args = events[0].values
    return BscGetfsstat64(events, args[0], args[1], args[2], serialize_result(events[-1], 'count'))


def handle_pthread_fchdir(parser, events):
    args = events[0].values
    return BscPthreadFchdir(events, args[0], serialize_result(events[-1]))


def handle_audit(parser, events):
    args = events[0].values
    return BscAudit(events, args[0], args[1], serialize_result(events[-1]))


def handle_auditon(parser, events):
    args = events[0].values
    return BscAuditon(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_getauid(parser, events):
    args = events[0].values
    return BscGetauid(events, args[0], serialize_result(events[-1]))


def handle_setauid(parser, events):
    args = events[0].values
    return BscSetauid(events, args[0], serialize_result(events[-1]))


def handle_bsdthread_create(parser, events):
    return BscBsdthreadCreate(events, events[-1].values[3])


def handle_kqueue(parser, events):
    return BscKqueue(events, serialize_result(events[-1], 'fd'))


def handle_kevent(parser, events):
    args = events[0].values
    return BscKevent(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_lchown(parser, events):
    args = events[0].values
    return BscLchown(events, parser.parse_vnode(events).path, args[1], args[2], serialize_result(events[-1]))


def handle_bsdthread_register(parser, events):
    args = events[0].values
    return BscBsdthreadRegister(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_workq_open(parser, events):
    return BscWorkqOpen(events, serialize_result(events[-1]))


def handle_workq_kernreturn(parser, events):
    args = events[0].values
    return BscWorkqKernreturn(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'return'))


def handle_kevent64(parser, events):
    args = events[0].values
    return BscKevent64(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_thread_selfid(parser, events):
    return BscThreadSelfid(events, serialize_result(events[-1], 'tid'))


def handle_kevent_qos(parser, events):
    args = events[0].values
    return BscKeventQos(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_kevent_id(parser, events):
    args = events[0].values
    return BscKeventId(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_mac_syscall(parser, events):
    args = events[0].values
    return BscMacSyscall(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_pselect(parser, events, no_cancel=False):
    args = events[0].values
    return BscPselect(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'), no_cancel)


def handle_fsgetpath(parser, events):
    args = events[0].values
    return BscFsgetpath(events, args[0], args[1], args[2], args[3], parser.parse_vnode(events).path,
                        serialize_result(events[-1], 'count'))


def handle_sys_fileport_makeport(parser, events):
    args = events[0].values
    return BscSysFileportMakeport(events, args[0], args[1], serialize_result(events[-1]))


def handle_sys_fileport_makefd(parser, events):
    args = events[0].values
    return BscSysFileportMakefd(events, args[0], serialize_result(events[-1], 'fd'))


def handle_audit_session_port(parser, events):
    args = events[0].values
    return BscAuditSessionPort(events, args[0], args[1], serialize_result(events[-1]))


def handle_pid_suspend(parser, events):
    args = events[0].values
    return BscPidSuspend(events, args[0], serialize_result(events[-1]))


def handle_pid_resume(parser, events):
    args = events[0].values
    return BscPidResume(events, args[0], serialize_result(events[-1]))


def handle_pid_hibernate(parser, events):
    args = events[0].values
    return BscPidHibernate(events, args[0], serialize_result(events[-1]))


def handle_pid_shutdown_sockets(parser, events):
    args = events[0].values
    return BscPidShutdownSockets(events, args[0], args[1], serialize_result(events[-1]))


def handle_shared_region_map_and_slide_np(parser, events):
    args = events[0].values
    return BscSharedRegionMapAndSlideNp(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_kas_info(parser, events):
    args = events[0].values
    return BscKasInfo(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_memorystatus_control(parser, events):
    args = events[0].values
    return BscMemorystatusControl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_guarded_open_np(parser, events):
    args = events[0].values
    return BscGuardedOpenNp(events, parser.parse_vnode(events).path, args[1], args[2], serialize_open_flags(args[3]),
                            serialize_result(events[-1], 'fd'))


def handle_guarded_close_np(parser, events):
    args = events[0].values
    return BscGuardedCloseNp(events, args[0], args[1], serialize_result(events[-1]))


def handle_guarded_kqueue_np(parser, events):
    args = events[0].values
    return BscGuardedKqueueNp(events, args[0], args[1], serialize_result(events[-1]))


def handle_change_fdguard_np(parser, events):
    args = events[0].values
    return BscChangeFdguardNp(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_usrctl(parser, events):
    args = events[0].values
    return BscUsrctl(events, args[0], serialize_result(events[-1]))


def handle_proc_rlimit_control(parser, events):
    args = events[0].values
    return BscProcRlimitControl(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_connectx(parser, events):
    args = events[0].values
    return BscConnectx(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_disconnectx(parser, events):
    args = events[0].values
    return BscDisconnectx(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_peeloff(parser, events):
    args = events[0].values
    return BscPeeloff(events, args[0], args[1], serialize_result(events[-1]))


def handle_socket_delegate(parser, events):
    args = events[0].values
    return BscSocketDelegate(events, socket.AddressFamily(args[0]), socket.SocketKind(args[1]), args[2], args[3],
                             serialize_result(events[-1], 'fd'))


def handle_telemetry(parser, events):
    args = events[0].values
    return BscTelemetry(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_proc_uuid_policy(parser, events):
    args = events[0].values
    return BscProcUuidPolicy(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_memorystatus_get_level(parser, events):
    return BscMemorystatusGetLevel(events, events[0].values[0], serialize_result(events[-1]))


def handle_system_override(parser, events):
    args = events[0].values
    return BscSystemOverride(events, args[0], args[1], serialize_result(events[-1]))


def handle_vfs_purge(parser, events):
    return BscVfsPurge(events, serialize_result(events[-1]))


def handle_sfi_ctl(parser, events):
    args = events[0].values
    return BscSfiCtl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_sfi_pidctl(parser, events):
    args = events[0].values
    return BscSfiPidctl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_coalition(parser, events):
    args = events[0].values
    return BscCoalition(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_coalition_info(parser, events):
    args = events[0].values
    return BscCoalitionInfo(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_necp_match_policy(parser, events):
    args = events[0].values
    return BscNecpMatchPolicy(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_getattrlistbulk(parser, events):
    args = events[0].values
    return BscGetattrlistbulk(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_clonefileat(parser, events):
    src = parser.parse_vnode(events)
    dst = parser.parse_vnode([e for e in events if e not in src.ktraces])
    args = events[0].values
    return BscClonefileat(events, args[0], src.path, args[2], dst.path, serialize_result(events[-1]))


def handle_openat(parser, events, no_cancel=False):
    vnode = parser.parse_vnode(events)
    call_flags = serialize_open_flags(events[0].values[2])
    return BscOpenat(events, events[0].values[0], vnode.path, call_flags, serialize_result(events[-1], 'fd'),
                     no_cancel)


def handle_renameat(parser, events):
    nodes = parser.parse_vnodes(events)
    args = events[0].values
    return BscRenameat(events, args[0], nodes[0].path, args[2], nodes[1].path, serialize_result(events[-1]))


def handle_faccessat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    amode = serialize_access_flags(args[2])
    return BscFaccessat(events, args[0], vnode.path, amode, args[3], serialize_result(events[-1]))


def handle_fchmodat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    mode = serialize_stat_flags(args[2])
    return BscFchmodat(events, args[0], vnode.path, mode, args[3], serialize_result(events[-1]))


def handle_fchownat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscFchownat(events, args[0], vnode.path, args[2], args[3], serialize_result(events[-1]))


def handle_fstatat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscFstatat(events, args[0], vnode.path, args[2], args[3], serialize_result(events[-1]))


def handle_fstatat64(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscFstatat64(events, args[0], vnode.path, args[2], args[3], serialize_result(events[-1]))


def handle_linkat(parser, events):
    nodes = parser.parse_vnodes(events)
    path1, path2 = (nodes[0].path, nodes[1].path) if nodes else ('', '')
    args = events[0].values
    return BscLinkat(events, args[0], path1, args[2], path2, serialize_result(events[-1]))


def handle_unlinkat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscUnlinkat(events, args[0], vnode.path, args[2], serialize_result(events[-1]))


def handle_readlinkat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscReadlinkat(events, args[0], vnode.path, args[2], args[3], serialize_result(events[-1], 'count'))


def handle_symlinkat(parser, events):
    nodes = parser.parse_vnodes(events)
    oldpath = nodes[0].path if len(nodes) > 1 else ''
    args = events[0].values
    return BscSymlinkat(events, oldpath, args[1], nodes[-1].path, serialize_result(events[-1]))


def handle_mkdirat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscMkdirat(events, args[0], vnode.path, serialize_stat_flags(args[2]), serialize_result(events[-1]))


def handle_getattrlistat(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscGetattrlistat(events, args[0], vnode.path, args[2], args[3], serialize_result(events[-1]))


def handle_proc_trace_log(parser, events):
    args = events[0].values
    return BscProcTraceLog(events, args[0], args[1], serialize_result(events[-1]))


def handle_bsdthread_ctl(parser, events):
    args = events[0].values
    return BscBsdthreadCtl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_openbyid_np(parser, events):
    args = events[0].values
    return BscOpenbyidNp(events, args[0], args[1], serialize_open_flags(args[2]),
                         serialize_result(events[-1], 'fd'))


def handle_recvmsg_x(parser, events):
    args = events[0].values
    return BscRecvmsgX(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_sendmsg_x(parser, events):
    args = events[0].values
    return BscSendmsgX(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_thread_selfusage(parser, events):
    return BscThreadSelfusage(events, serialize_result(events[-1], 'runtime'))


def handle_csrctl(parser, events):
    args = events[0].values
    return BscCsrctl(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_guarded_open_dprotected_np(parser, events):
    vnode = parser.parse_vnode(events)
    args = events[0].values
    return BscGuardedOpenDprotectedNp(events, vnode.path, args[1], args[2], serialize_open_flags(args[3]),
                                      serialize_result(events[-1], 'fd'))


def handle_guarded_write_np(parser, events):
    args = events[0].values
    return BscGuardedWriteNp(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_guarded_pwrite_np(parser, events):
    args = events[0].values
    return BscGuardedPwriteNp(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_guarded_writev_np(parser, events):
    args = events[0].values
    return BscGuardedWritevNp(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_renameatx_np(parser, events):
    nodes = parser.parse_vnodes(events)
    path1, path2 = (nodes[0].path, nodes[1].path) if nodes else ('', '')
    args = events[0].values
    return BscRenameatxNp(events, args[0], path1, args[2], path2, serialize_result(events[-1]))


def handle_mremap_encrypted(parser, events):
    args = events[0].values
    return BscMremapEncrypted(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_netagent_trigger(parser, events):
    args = events[0].values
    return BscNetagentTrigger(events, args[0], args[1], serialize_result(events[-1]))


def handle_stack_snapshot_with_config(parser, events):
    args = events[0].values
    return BscStackSnapshotWithConfig(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_microstackshot(parser, events):
    args = events[0].values
    return BscMicrostackshot(events, args[0], args[1], args[2], serialize_result(events[-1], 'count'))


def handle_grab_pgo_data(parser, events):
    args = events[0].values
    return BscGrabPgoData(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'count'))


def handle_persona(parser, events):
    args = events[0].values
    return BscPersona(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_mach_eventlink_signal(parser, events):
    args = events[0].values
    return BscMachEventlinkSignal(events, args[0], args[1], serialize_result(events[-1]))


def handle_mach_eventlink_wait_until(parser, events):
    args = events[0].values
    return BscMachEventlinkWaitUntil(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_mach_eventlink_signal_wait_until(parser, events):
    args = events[0].values
    return BscMachEventlinkSignalWaitUntil(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_work_interval_ctl(parser, events):
    args = events[0].values
    return BscWorkIntervalCtl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_getentropy(parser, events):
    args = events[0].values
    return BscGetentropy(events, args[0], args[1], serialize_result(events[-1]))


def handle_necp_open(parser, events):
    args = events[0].values
    return BscNecpOpen(events, args[0], serialize_result(events[-1], 'fd'))


def handle_necp_client_action(parser, events):
    args = events[0].values
    return BscNecpClientAction(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'return'))


def handle_nexus_open(parser, events):
    return BscNexusOpen(events, serialize_result(events[-1], 'fd'))


def handle_nexus_register(parser, events):
    return BscNexusRegister(events, serialize_result(events[-1]))


def handle_nexus_deregister(parser, events):
    return BscNexusDeregister(events, serialize_result(events[-1]))


def handle_nexus_create(parser, events):
    return BscNexusCreate(events, serialize_result(events[-1]))


def handle_nexus_destroy(parser, events):
    return BscNexusDestroy(events, serialize_result(events[-1]))


def handle_nexus_get_opt(parser, events):
    return BscNexusGetOpt(events, serialize_result(events[-1]))


def handle_nexus_set_opt(parser, events):
    return BscNexusSetOpt(events, serialize_result(events[-1]))


def handle_channel_open(parser, events):
    return BscChannelOpen(events, serialize_result(events[-1]))


def handle_channel_get_info(parser, events):
    return BscChannelGetInfo(events, serialize_result(events[-1]))


def handle_channel_sync(parser, events):
    return BscChannelSync(events, serialize_result(events[-1]))


def handle_channel_get_opt(parser, events):
    return BscChannelGetOpt(events, serialize_result(events[-1]))


def handle_channel_set_opt(parser, events):
    return BscChannelSetOpt(events, serialize_result(events[-1]))


def handle_ulock_wait(parser, events):
    args = events[0].values
    return BscUlockWait(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'return'))


def handle_ulock_wake(parser, events):
    args = events[0].values
    return BscUlockWake(events, args[0], args[1], args[2], serialize_result(events[-1], 'return'))


def handle_fclonefileat(parser, events):
    args = events[0].values
    return BscFclonefileat(events, args[0], args[1], parser.parse_vnode(events).path, args[3],
                           serialize_result(events[-1]))


def handle_fs_snapshot(parser, events):
    nodes = parser.parse_vnodes(events)
    name2 = nodes[1].path if len(nodes) > 1 else ''
    args = events[0].values
    return BscFsSnapshot(events, FsSnapshotOp(args[0]), args[1], nodes[0].path, name2, serialize_result(events[-1]))


def handle_terminate_with_payload(parser, events):
    args = events[0].values
    return BscTerminateWithPayload(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_abort_with_payload(parser, events):
    args = events[0].values
    return BscAbortWithPayload(events, args[0], args[1], args[2], args[3])


def handle_necp_session_open(parser, events):
    args = events[0].values
    return BscNecpSessionOpen(events, args[0], serialize_result(events[-1], 'fd'))


def handle_necp_session_action(parser, events):
    args = events[0].values
    return BscNecpSessionAction(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_setattrlistat(parser, events):
    args = events[0].values
    return BscSetattrlistat(events, args[0], parser.parse_vnode(events).path, args[2], args[3],
                            serialize_result(events[-1]))


def handle_net_qos_guideline(parser, events):
    args = events[0].values
    return BscNetQosGuideline(events, args[0], args[1], serialize_result(events[-1], 'background'))


def handle_fmount(parser, events):
    args = events[0].values
    return BscFmount(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_ntp_adjtime(parser, events):
    args = events[0].values
    return BscNtpAdjtime(events, args[0], serialize_result(events[-1], 'return'))


def handle_ntp_gettime(parser, events):
    args = events[0].values
    return BscNtpGettime(events, args[0], serialize_result(events[-1]))


def handle_os_fault_with_payload(parser, events):
    args = events[0].values
    return BscOsFaultWithPayload(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_kqueue_workloop_ctl(parser, events):
    args = events[0].values
    return BscKqueueWorkloopCtl(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_mach_bridge_remote_time(parser, events):
    args = events[0].values
    return BscMachBridgeRemoteTime(events, args[0], serialize_result(events[-1]))


def handle_coalition_ledger(parser, events):
    args = events[0].values
    return BscCoalitionLedger(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_log_data(parser, events):
    args = events[0].values
    return BscLogData(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_memorystatus_available_memory(parser, events):
    return BscMemorystatusAvailableMemory(events, serialize_result(events[-1], 'count'))


def handle_shared_region_map_and_slide_2_np(parser, events):
    args = events[0].values
    return BscSharedRegionMapAndSlide2Np(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


def handle_pivot_root(parser, events):
    nodes = parser.parse_vnodes(events)
    path1, path2 = (nodes[0].path, nodes[1].path) if nodes else ('', '')
    return BscPivotRoot(events, path1, path2, serialize_result(events[-1]))


def handle_task_inspect_for_pid(parser, events):
    args = events[0].values
    return BscTaskInspectForPid(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_task_read_for_pid(parser, events):
    args = events[0].values
    return BscTaskReadForPid(events, args[0], args[1], args[2], serialize_result(events[-1]))


def handle_sys_preadv(parser, events, no_cancel=False):
    args = events[0].values
    return BscSysPreadv(events, args[0], args[1], args[2], ctypes.c_int64(args[0]).value,
                        serialize_result(events[-1], 'count'), no_cancel)


def handle_sys_pwritev(parser, events, no_cancel=False):
    args = events[0].values
    return BscSysPwritev(events, args[0], args[1], args[2], ctypes.c_int64(args[0]).value,
                         serialize_result(events[-1], 'count'), no_cancel)


def handle_ulock_wait2(parser, events):
    args = events[0].values
    return BscUlockWait2(events, args[0], args[1], args[2], args[3], serialize_result(events[-1], 'return'))


def handle_proc_info_extended_id(parser, events):
    args = events[0].values
    return BscProcInfoExtendedId(events, args[0], args[1], args[2], args[3], serialize_result(events[-1]))


handlers = {
    'BSC_read': handle_read,
    'BSC_write': handle_write,
    'BSC_open': handle_open,
    'BSC_sys_close': handle_sys_close,
    'BSC_link': handle_link,
    'BSC_unlink': handle_unlink,
    'BSC_chdir': handle_chdir,
    'BSC_fchdir': handle_fchdir,
    'BSC_mknod': handle_mknod,
    'BSC_chmod': handle_chmod,
    'BSC_chown': handle_chown,
    'BSC_getpid': handle_getpid,
    'BSC_setuid': handle_setuid,
    'BSC_getuid': handle_getuid,
    'BSC_geteuid': handle_geteuid,
    'BSC_recvmsg': handle_recvmsg,
    'BSC_sendmsg': handle_sendmsg,
    'BSC_recvfrom': handle_recvfrom,
    'BSC_accept': handle_accept,
    'BSC_getpeername': handle_getpeername,
    'BSC_getsockname': handle_getsockname,
    'BSC_access': handle_access,
    'BSC_chflags': handle_chflags,
    'BSC_fchflags': handle_fchflags,
    'BSC_sync': handle_sync,
    'BSC_kill': handle_kill,
    'BSC_getppid': handle_getppid,
    'BSC_sys_dup': handle_sys_dup,
    'BSC_pipe': handle_pipe,
    'BSC_getegid': handle_getegid,
    'BSC_sigaction': handle_sigaction,
    'BSC_getgid': handle_getgid,
    'BSC_sigprocmask': handle_sigprocmask,
    'BSC_getlogin': handle_getlogin,
    'BSC_setlogin': handle_setlogin,
    'BSC_acct': handle_acct,
    'BSC_sigpending': handle_sigpending,
    'BSC_sigaltstack': handle_sigaltstack,
    'BSC_ioctl': handle_ioctl,
    'BSC_reboot': handle_reboot,
    'BSC_revoke': handle_revoke,
    'BSC_symlink': handle_symlink,
    'BSC_readlink': handle_readlink,
    'BSC_execve': handle_execve,
    'BSC_umask': handle_umask,
    'BSC_chroot': handle_chroot,
    'BSC_msync': handle_msync,
    'BSC_vfork': handle_vfork,
    'BSC_munmap': handle_munmap,
    'BSC_mprotect': handle_mprotect,
    'BSC_madvise': handle_madvise,
    'BSC_mincore': handle_mincore,
    'BSC_getgroups': handle_getgroups,
    'BSC_setgroups': handle_setgroups,
    'BSC_getpgrp': handle_getpgrp,
    'BSC_setpgid': handle_setpgid,
    'BSC_setitimer': handle_setitimer,
    'BSC_swapon': handle_swapon,
    'BSC_getitimer': handle_getitimer,
    'BSC_sys_getdtablesize': handle_sys_getdtablesize,
    'BSC_sys_dup2': handle_sys_dup2,
    'BSC_sys_fcntl': handle_sys_fcntl,
    'BSC_select': handle_select,
    'BSC_fsync': handle_fsync,
    'BSC_setpriority': handle_setpriority,
    'BSC_socket': handle_socket,
    'BSC_connect': handle_connect,
    'BSC_getpriority': handle_getpriority,
    'BSC_bind': handle_bind,
    'BSC_setsockopt': handle_setsockopt,
    'BSC_listen': handle_listen,
    'BSC_sigsuspend': handle_sigsuspend,
    'BSC_gettimeofday': handle_gettimeofday,
    'BSC_getrusage': handle_getrusage,
    'BSC_getsockopt': handle_getsockopt,
    'BSC_readv': handle_readv,
    'BSC_writev': handle_writev,
    'BSC_settimeofday': handle_settimeofday,
    'BSC_fchown': handle_fchown,
    'BSC_fchmod': handle_fchmod,
    'BSC_setreuid': handle_setreuid,
    'BSC_setregid': handle_setregid,
    'BSC_rename': handle_rename,
    'BSC_sys_flock': handle_sys_flock,
    'BSC_mkfifo': handle_mkfifo,
    'BSC_sendto': handle_sendto,
    'BSC_shutdown': handle_shutdown,
    'BSC_socketpair': handle_socketpair,
    'BSC_mkdir': handle_mkdir,
    'BSC_rmdir': handle_rmdir,
    'BSC_utimes': handle_utimes,
    'BSC_futimes': handle_futimes,
    'BSC_adjtime': handle_adjtime,
    'BSC_gethostuuid': handle_gethostuuid,
    'BSC_obs_killpg': handle_obs_killpg,
    'BSC_setsid': handle_setsid,
    'BSC_getpgid': handle_getpgid,
    'BSC_setprivexec': handle_setprivexec,
    'BSC_pread': handle_pread,
    'BSC_pwrite': handle_pwrite,
    'BSC_nfssvc': handle_nfssvc,
    'BSC_statfs': handle_statfs,
    'BSC_fstatfs': handle_fstatfs,
    'BSC_unmount': handle_unmount,
    'BSC_getfh': handle_getfh,
    'BSC_quotactl': handle_quotactl,
    'BSC_mount': handle_mount,
    'BSC_csops': handle_csops,
    'BSC_csops_audittoken': handle_csops_audittoken,
    'BSC_waitid': handle_waitid,
    'BSC_kdebug_typefilter': handle_kdebug_typefilter,
    'BSC_setgid': handle_setgid,
    'BSC_setegid': handle_setegid,
    'BSC_seteuid': handle_seteuid,
    'BSC_thread_selfcounts': handle_thread_selfcounts,
    'BSC_fdatasync': handle_fdatasync,
    'BSC_pathconf': handle_pathconf,
    'BSC_sys_fpathconf': handle_sys_fpathconf,
    'BSC_getrlimit': handle_getrlimit,
    'BSC_setrlimit': handle_setrlimit,
    'BSC_getdirentries': handle_getdirentries,
    'BSC_mmap': handle_mmap,
    'BSC_lseek': handle_lseek,
    'BSC_truncate': handle_truncate,
    'BSC_ftruncate': handle_ftruncate,
    'BSC_sysctl': handle_sysctl,
    'BSC_mlock': handle_mlock,
    'BSC_munlock': handle_munlock,
    'BSC_undelete': handle_undelete,
    'BSC_open_dprotected_np': handle_open_dprotected_np,
    'BSC_getattrlist': handle_getattrlist,
    'BSC_setattrlist': handle_setattrlist,
    'BSC_getdirentriesattr': handle_getdirentriesattr,
    'BSC_exchangedata': handle_exchangedata,
    'BSC_searchfs': handle_searchfs,
    'BSC_fgetattrlist': handle_fgetattrlist,
    'BSC_fsetattrlist': handle_fsetattrlist,
    'BSC_poll': handle_poll,
    'BSC_getxattr': handle_getxattr,
    'BSC_fgetxattr': handle_fgetxattr,
    'BSC_setxattr': handle_setxattr,
    'BSC_fsetxattr': handle_fsetxattr,
    'BSC_removexattr': handle_removexattr,
    'BSC_fremovexattr': handle_fremovexattr,
    'BSC_listxattr': handle_listxattr,
    'BSC_flistxattr': handle_flistxattr,
    'BSC_fsctl': handle_fsctl,
    'BSC_initgroups': handle_initgroups,
    'BSC_posix_spawn': handle_posix_spawn,
    'BSC_ffsctl': handle_ffsctl,
    'BSC_nfsclnt': handle_nfsclnt,
    'BSC_fhopen': handle_fhopen,
    'BSC_minherit': handle_minherit,
    'BSC_semsys': handle_semsys,
    'BSC_msgsys': handle_msgsys,
    'BSC_shmsys': handle_shmsys,
    'BSC_semctl': handle_semctl,
    'BSC_semget': handle_semget,
    'BSC_semop': handle_semop,
    'BSC_msgctl': handle_msgctl,
    'BSC_msgget': handle_msgget,
    'BSC_msgsnd': handle_msgsnd,
    'BSC_msgrcv': handle_msgrcv,
    'BSC_shmat': handle_shmat,
    'BSC_shmctl': handle_shmctl,
    'BSC_shmdt': handle_shmdt,
    'BSC_shmget': handle_shmget,
    'BSC_shm_open': handle_shm_open,
    'BSC_shm_unlink': handle_shm_unlink,
    'BSC_sem_open': handle_sem_open,
    'BSC_sem_close': handle_sem_close,
    'BSC_sem_unlink': handle_sem_unlink,
    'BSC_sem_wait': handle_sem_wait,
    'BSC_sem_trywait': handle_sem_trywait,
    'BSC_sem_post': handle_sem_post,
    'BSC_sys_sysctlbyname': handle_sys_sysctlbyname,
    'BSC_access_extended': handle_access_extended,
    'BSC_gettid': handle_gettid,
    'BSC_shared_region_check_np': handle_shared_region_check_np,
    'BSC_psynch_mutexwait': handle_psynch_mutexwait,
    'BSC_psynch_mutexdrop': handle_psynch_mutexdrop,
    'BSC_psynch_cvbroad': handle_psynch_cvbroad,
    'BSC_psynch_cvsignal': handle_psynch_cvsignal,
    'BSC_psynch_cvwait': handle_psynch_cvwait,
    'BSC_getsid': handle_getsid,
    'BSC_psynch_cvclrprepost': handle_psynch_cvclrprepost,
    'BSC_iopolicysys': handle_iopolicysys,
    'BSC_process_policy': handle_process_policy,
    'BSC_mlockall': handle_mlockall,
    'BSC_munlockall': handle_munlockall,
    'BSC_issetugid': handle_issetugid,
    'BSC_pthread_sigmask': handle_pthread_sigmask,
    'BSC_disable_threadsignal': handle_disable_threadsignal,
    'BSC_semwait_signal': handle_semwait_signal,
    'BSC_proc_info': handle_proc_info,
    'BSC_sendfile': handle_sendfile,
    'BSC_stat64': handle_stat64,
    'BSC_sys_fstat64': handle_sys_fstat64,
    'BSC_lstat64': handle_lstat64,
    'BSC_getdirentries64': handle_getdirentries64,
    'BSC_statfs64': handle_statfs64,
    'BSC_fstatfs64': handle_fstatfs64,
    'BSC_getfsstat64': handle_getfsstat64,
    'BSC_pthread_fchdir': handle_pthread_fchdir,
    'BSC_audit': handle_audit,
    'BSC_auditon': handle_auditon,
    'BSC_getauid': handle_getauid,
    'BSC_setauid': handle_setauid,
    'BSC_bsdthread_create': handle_bsdthread_create,
    'BSC_kqueue': handle_kqueue,
    'BSC_kevent': handle_kevent,
    'BSC_lchown': handle_lchown,
    'BSC_bsdthread_register': handle_bsdthread_register,
    'BSC_workq_open': handle_workq_open,
    'BSC_workq_kernreturn': handle_workq_kernreturn,
    'BSC_kevent64': handle_kevent64,
    'BSC_thread_selfid': handle_thread_selfid,
    'BSC_kevent_qos': handle_kevent_qos,
    'BSC_kevent_id': handle_kevent_id,
    'BSC_mac_syscall': handle_mac_syscall,
    'BSC_pselect': handle_pselect,
    'BSC_pselect_nocancel': partial(handle_pselect, no_cancel=True),
    'BSC_read_nocancel': partial(handle_read, no_cancel=True),
    'BSC_write_nocancel': partial(handle_write, no_cancel=True),
    'BSC_open_nocancel': partial(handle_open, no_cancel=True),
    'BSC_sys_close_nocancel': partial(handle_sys_close, no_cancel=True),
    'BSC_wait4_nocancel': partial(handle_wait4, no_cancel=True),
    'BSC_recvmsg_nocancel': partial(handle_recvmsg, no_cancel=True),
    'BSC_sendmsg_nocancel': partial(handle_sendmsg, no_cancel=True),
    'BSC_recvfrom_nocancel': partial(handle_recvfrom, no_cancel=True),
    'BSC_accept_nocancel': partial(handle_accept, no_cancel=True),
    'BSC_msync_nocancel': partial(handle_msync, no_cancel=True),
    'BSC_sys_fcntl_nocancel': partial(handle_sys_fcntl, no_cancel=True),
    'BSC_select_nocancel': partial(handle_select, no_cancel=True),
    'BSC_fsync_nocancel': partial(handle_fsync, no_cancel=True),
    'BSC_connect_nocancel': partial(handle_connect, no_cancel=True),
    'BSC_sigsuspend_nocancel': partial(handle_sigsuspend, no_cancel=True),
    'BSC_readv_nocancel': partial(handle_readv, no_cancel=True),
    'BSC_writev_nocancel': partial(handle_writev, no_cancel=True),
    'BSC_sendto_nocancel': partial(handle_sendto, no_cancel=True),
    'BSC_pread_nocancel': partial(handle_pread, no_cancel=True),
    'BSC_pwrite_nocancel': partial(handle_pwrite, no_cancel=True),
    'BSC_waitid_nocancel': partial(handle_waitid, no_cancel=True),
    'BSC_poll_nocancel': partial(handle_poll, no_cancel=True),
    'BSC_msgsnd_nocancel': partial(handle_msgsnd, no_cancel=True),
    'BSC_msgrcv_nocancel': partial(handle_msgrcv, no_cancel=True),
    'BSC_sem_wait_nocancel': partial(handle_sem_wait, no_cancel=True),
    'BSC_semwait_signal_nocancel': partial(handle_semwait_signal, no_cancel=True),
    'BSC_fsgetpath': handle_fsgetpath,
    'BSC_sys_fileport_makeport': handle_sys_fileport_makeport,
    'BSC_sys_fileport_makefd': handle_sys_fileport_makefd,
    'BSC_audit_session_port': handle_audit_session_port,
    'BSC_pid_suspend': handle_pid_suspend,
    'BSC_pid_resume': handle_pid_resume,
    'BSC_pid_hibernate': handle_pid_hibernate,
    'BSC_pid_shutdown_sockets': handle_pid_shutdown_sockets,
    'BSC_shared_region_map_and_slide_np': handle_shared_region_map_and_slide_np,
    'BSC_kas_info': handle_kas_info,
    'BSC_memorystatus_control': handle_memorystatus_control,
    'BSC_guarded_open_np': handle_guarded_open_np,
    'BSC_guarded_close_np': handle_guarded_close_np,
    'BSC_guarded_kqueue_np': handle_guarded_kqueue_np,
    'BSC_change_fdguard_np': handle_change_fdguard_np,
    'BSC_usrctl': handle_usrctl,
    'BSC_proc_rlimit_control': handle_proc_rlimit_control,
    'BSC_connectx': handle_connectx,
    'BSC_disconnectx': handle_disconnectx,
    'BSC_peeloff': handle_peeloff,
    'BSC_socket_delegate': handle_socket_delegate,
    'BSC_telemetry': handle_telemetry,
    'BSC_proc_uuid_policy': handle_proc_uuid_policy,
    'BSC_memorystatus_get_level': handle_memorystatus_get_level,
    'BSC_system_override': handle_system_override,
    'BSC_vfs_purge': handle_vfs_purge,
    'BSC_sfi_ctl': handle_sfi_ctl,
    'BSC_sfi_pidctl': handle_sfi_pidctl,
    'BSC_coalition': handle_coalition,
    'BSC_coalition_info': handle_coalition_info,
    'BSC_necp_match_policy': handle_necp_match_policy,
    'BSC_getattrlistbulk': handle_getattrlistbulk,
    'BSC_clonefileat': handle_clonefileat,
    'BSC_openat': handle_openat,
    'BSC_openat_nocancel': partial(handle_openat, no_cancel=True),
    'BSC_renameat': handle_renameat,
    'BSC_faccessat': handle_faccessat,
    'BSC_fchmodat': handle_fchmodat,
    'BSC_fchownat': handle_fchownat,
    'BSC_fstatat': handle_fstatat,
    'BSC_fstatat64': handle_fstatat64,
    'BSC_linkat': handle_linkat,
    'BSC_unlinkat': handle_unlinkat,
    'BSC_readlinkat': handle_readlinkat,
    'BSC_symlinkat': handle_symlinkat,
    'BSC_mkdirat': handle_mkdirat,
    'BSC_getattrlistat': handle_getattrlistat,
    'BSC_proc_trace_log': handle_proc_trace_log,
    'BSC_bsdthread_ctl': handle_bsdthread_ctl,
    'BSC_openbyid_np': handle_openbyid_np,
    'BSC_recvmsg_x': handle_recvmsg_x,
    'BSC_sendmsg_x': handle_sendmsg_x,
    'BSC_thread_selfusage': handle_thread_selfusage,
    'BSC_csrctl': handle_csrctl,
    'BSC_guarded_open_dprotected_np': handle_guarded_open_dprotected_np,
    'BSC_guarded_write_np': handle_guarded_write_np,
    'BSC_guarded_pwrite_np': handle_guarded_pwrite_np,
    'BSC_guarded_writev_np': handle_guarded_writev_np,
    'BSC_renameatx_np': handle_renameatx_np,
    'BSC_mremap_encrypted': handle_mremap_encrypted,
    'BSC_netagent_trigger': handle_netagent_trigger,
    'BSC_stack_snapshot_with_config': handle_stack_snapshot_with_config,
    'BSC_microstackshot': handle_microstackshot,
    'BSC_grab_pgo_data': handle_grab_pgo_data,
    'BSC_persona': handle_persona,
    'BSC_mach_eventlink_signal': handle_mach_eventlink_signal,
    'BSC_mach_eventlink_wait_until': handle_mach_eventlink_wait_until,
    'BSC_mach_eventlink_signal_wait_until': handle_mach_eventlink_signal_wait_until,
    'BSC_work_interval_ctl': handle_work_interval_ctl,
    'BSC_getentropy': handle_getentropy,
    'BSC_necp_open': handle_necp_open,
    'BSC_necp_client_action': handle_necp_client_action,
    'BSC_nexus_open': handle_nexus_open,
    'BSC_nexus_register': handle_nexus_register,
    'BSC_nexus_deregister': handle_nexus_deregister,
    'BSC_nexus_create': handle_nexus_create,
    'BSC_nexus_destroy': handle_nexus_destroy,
    'BSC_nexus_get_opt': handle_nexus_get_opt,
    'BSC_nexus_set_opt': handle_nexus_set_opt,
    'BSC_channel_open': handle_channel_open,
    'BSC_channel_get_info': handle_channel_get_info,
    'BSC_channel_sync': handle_channel_sync,
    'BSC_channel_get_opt': handle_channel_get_opt,
    'BSC_channel_set_opt': handle_channel_set_opt,
    'BSC_ulock_wait': handle_ulock_wait,
    'BSC_ulock_wake': handle_ulock_wake,
    'BSC_fclonefileat': handle_fclonefileat,
    'BSC_fs_snapshot': handle_fs_snapshot,
    'BSC_terminate_with_payload': handle_terminate_with_payload,
    'BSC_abort_with_payload': handle_abort_with_payload,
    'BSC_necp_session_open': handle_necp_session_open,
    'BSC_necp_session_action': handle_necp_session_action,
    'BSC_setattrlistat': handle_setattrlistat,
    'BSC_net_qos_guideline': handle_net_qos_guideline,
    'BSC_fmount': handle_fmount,
    'BSC_ntp_adjtime': handle_ntp_adjtime,
    'BSC_ntp_gettime': handle_ntp_gettime,
    'BSC_os_fault_with_payload': handle_os_fault_with_payload,
    'BSC_kqueue_workloop_ctl': handle_kqueue_workloop_ctl,
    'BSC_mach_bridge_remote_time': handle_mach_bridge_remote_time,
    'BSC_coalition_ledger': handle_coalition_ledger,
    'BSC_log_data': handle_log_data,
    'BSC_memorystatus_available_memory': handle_memorystatus_available_memory,
    'BSC_shared_region_map_and_slide_2_np': handle_shared_region_map_and_slide_2_np,
    'BSC_pivot_root': handle_pivot_root,
    'BSC_task_inspect_for_pid': handle_task_inspect_for_pid,
    'BSC_task_read_for_pid': handle_task_read_for_pid,
    'BSC_sys_preadv': handle_sys_preadv,
    'BSC_sys_pwritev': handle_sys_pwritev,
    'BSC_sys_preadv_nocancel': partial(handle_sys_preadv, no_cancel=True),
    'BSC_sys_pwritev_nocancel': partial(handle_sys_pwritev, no_cancel=True),
    'BSC_ulock_wait2': handle_ulock_wait2,
    'BSC_proc_info_extended_id': handle_proc_info_extended_id,
}
