import ctypes
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import List


class AsynchronousSystemTrapsReason(Enum):
    AST_NONE = 0x00
    AST_PREEMPT = 0x01
    AST_QUANTUM = 0x02
    AST_URGENT = 0x04
    AST_HANDOFF = 0x08
    AST_YIELD = 0x10
    AST_APC = 0x20
    AST_LEDGER = 0x40
    AST_BSD = 0x80
    AST_KPERF = 0x100
    AST_MACF = 0x200
    AST_RESET_PCS = 0x400
    AST_ARCADE = 0x800
    AST_GUARD = 0x1000
    AST_TELEMETRY_USER = 0x2000
    AST_TELEMETRY_KERNEL = 0x4000
    AST_TELEMETRY_PMI = 0x8000
    AST_SFI = 0x10000
    AST_DTRACE = 0x20000
    AST_TELEMETRY_IO = 0x40000
    AST_KEVENT = 0x80000
    AST_REBALANCE = 0x100000
    AST_UNQUIESCE = 0x200000


def to_ast_reasons(flags: int):
    if not flags:
        return [AsynchronousSystemTrapsReason.AST_NONE]
    else:
        return [r for r in AsynchronousSystemTrapsReason if r.value & flags]


# osfmk/arm64/proc_reg.h

ESR_EC_SHIFT = 26


class ExceptionSyndromeRegisterClass(Enum):
    ESR_EC_UNCATEGORIZED = 0x00
    ESR_EC_WFI_WFE = 0x01
    ESR_EC_MCR_MRC_CP15_TRAP = 0x03
    ESR_EC_MCRR_MRRC_CP15_TRAP = 0x04
    ESR_EC_MCR_MRC_CP14_TRAP = 0x05
    ESR_EC_LDC_STC_CP14_TRAP = 0x06
    ESR_EC_TRAP_SIMD_FP = 0x07
    ESR_EC_PTRAUTH_INSTR_TRAP = 0x09
    ESR_EC_MCRR_MRRC_CP14_TRAP = 0x0c
    ESR_EC_ILLEGAL_INSTR_SET = 0x0e
    ESR_EC_SVC_32 = 0x11
    ESR_EC_SVC_64 = 0x15
    ESR_EC_MSR_TRAP = 0x18
    ESR_EC_IABORT_EL0 = 0x20
    ESR_EC_IABORT_EL1 = 0x21
    ESR_EC_PC_ALIGN = 0x22
    ESR_EC_DABORT_EL0 = 0x24
    ESR_EC_DABORT_EL1 = 0x25
    ESR_EC_SP_ALIGN = 0x26
    ESR_EC_FLOATING_POINT_32 = 0x28
    ESR_EC_FLOATING_POINT_64 = 0x2C
    ESR_EC_BKPT_REG_MATCH_EL0 = 0x30
    ESR_EC_BKPT_REG_MATCH_EL1 = 0x31
    ESR_EC_SW_STEP_DEBUG_EL0 = 0x32
    ESR_EC_SW_STEP_DEBUG_EL1 = 0x33
    ESR_EC_WATCHPT_MATCH_EL0 = 0x34
    ESR_EC_WATCHPT_MATCH_EL1 = 0x35
    ESR_EC_BKPT_AARCH32 = 0x38
    ESR_EC_BRK_AARCH64 = 0x3C


class ThreadState(Enum):
    TH_WAIT = 0x01
    TH_SUSP = 0x02
    TH_RUN = 0x04
    TH_UNINT = 0x08
    TH_TERMINATE = 0x10
    TH_TERMINATE2 = 0x20
    TH_WAIT_REPORT = 0x40
    TH_IDLE = 0x80


def to_thread_state(flags: int):
    return [s for s in ThreadState if s.value & flags]


class InterruptType(Enum):
    DBG_INTR_TYPE_UNKNOWN = 0x0
    DBG_INTR_TYPE_IPI = 0x1
    DBG_INTR_TYPE_TIMER = 0x2
    DBG_INTR_TYPE_OTHER = 0x3
    DBG_INTR_TYPE_PMI = 0x4


class ProcessState(Enum):
    PROCESSOR_OFF_LINE = 0
    PROCESSOR_SHUTDOWN = 1
    PROCESSOR_START = 2
    PROCESSOR_UNUSED = 3
    PROCESSOR_IDLE = 4
    PROCESSOR_DISPATCHING = 5
    PROCESSOR_RUNNING = 6


class DbgVmFaultType(Enum):
    DBG_ZERO_FILL_FAULT = 1
    DBG_PAGEIN_FAULT = 2
    DBG_COW_FAULT = 3
    DBG_CACHE_HIT_FAULT = 4
    DBG_NZF_PAGE_FAULT = 5
    DBG_GUARD_FAULT = 6
    DBG_PAGEINV_FAULT = 7
    DBG_PAGEIND_FAULT = 8
    DBG_COMPRESSOR_FAULT = 9
    DBG_COMPRESSOR_SWAPIN_FAULT = 10
    DBG_COR_FAULT = 11


class VmProtection(Enum):
    VM_PROT_NONE = 0x00
    VM_PROT_READ = 0x01
    VM_PROT_WRITE = 0x02
    VM_PROT_EXECUTE = 0x04
    VM_PROT_NO_CHANGE = 0x08
    VM_PROT_COPY = 0x10
    VM_PROT_TRUSTED = 0x20
    VM_PROT_IS_MASK = 0x40
    VM_PROT_STRIP_READ = 0x80


def to_vm_prot(flags: int):
    if not flags:
        return [VmProtection.VM_PROT_NONE]
    else:
        return [p for p in VmProtection if p.value & flags]


# osfmk/mach/port.h

class MachPortRight(Enum):
    MACH_PORT_RIGHT_SEND = 0
    MACH_PORT_RIGHT_RECEIVE = 1
    MACH_PORT_RIGHT_SEND_ONCE = 2
    MACH_PORT_RIGHT_PORT_SET = 3
    MACH_PORT_RIGHT_DEAD_NAME = 4
    MACH_PORT_RIGHT_NUMBER = 5


# osfmk/mach/message.h

class MachMsgTypeName(Enum):
    MACH_MSG_TYPE_MOVE_RECEIVE = 16
    MACH_MSG_TYPE_MOVE_SEND = 17
    MACH_MSG_TYPE_MOVE_SEND_ONCE = 18
    MACH_MSG_TYPE_COPY_SEND = 19
    MACH_MSG_TYPE_MAKE_SEND = 20
    MACH_MSG_TYPE_MAKE_SEND_ONCE = 21
    MACH_MSG_TYPE_COPY_RECEIVE = 22


# osfmk/mach/kern_return.h

class KernReturn(Enum):
    KERN_SUCCESS = 0
    KERN_INVALID_ADDRESS = 1
    KERN_PROTECTION_FAILURE = 2
    KERN_NO_SPACE = 3
    KERN_INVALID_ARGUMENT = 4
    KERN_FAILURE = 5
    KERN_RESOURCE_SHORTAGE = 6
    KERN_NOT_RECEIVER = 7
    KERN_NO_ACCESS = 8
    KERN_MEMORY_FAILURE = 9
    KERN_MEMORY_ERROR = 10
    KERN_ALREADY_IN_SET = 11
    KERN_NOT_IN_SET = 12
    KERN_NAME_EXISTS = 13
    KERN_ABORTED = 14
    KERN_INVALID_NAME = 15
    KERN_INVALID_TASK = 16
    KERN_INVALID_RIGHT = 17
    KERN_INVALID_VALUE = 18
    KERN_UREFS_OVERFLOW = 19
    KERN_INVALID_CAPABILITY = 20
    KERN_RIGHT_EXISTS = 21
    KERN_INVALID_HOST = 22
    KERN_MEMORY_PRESENT = 23
    KERN_MEMORY_DATA_MOVED = 24
    KERN_MEMORY_RESTART_COPY = 25
    KERN_INVALID_PROCESSOR_SET = 26
    KERN_POLICY_LIMIT = 27
    KERN_INVALID_POLICY = 28
    KERN_INVALID_OBJECT = 29
    KERN_ALREADY_WAITING = 30
    KERN_DEFAULT_SET = 31
    KERN_EXCEPTION_PROTECTED = 32
    KERN_INVALID_LEDGER = 33
    KERN_INVALID_MEMORY_CONTROL = 34
    KERN_INVALID_SECURITY = 35
    KERN_NOT_DEPRESSED = 36
    KERN_TERMINATED = 37
    KERN_LOCK_SET_DESTROYED = 38
    KERN_LOCK_UNSTABLE = 39
    KERN_LOCK_OWNED = 40
    KERN_LOCK_OWNED_SELF = 41
    KERN_SEMAPHORE_DESTROYED = 42
    KERN_RPC_SERVER_TERMINATED = 43
    KERN_RPC_TERMINATE_ORPHAN = 44
    KERN_RPC_CONTINUE_ORPHAN = 45
    KERN_NOT_SUPPORTED = 46
    KERN_NODE_DOWN = 47
    KERN_NOT_WAITING = 48
    KERN_OPERATION_TIMED_OUT = 49
    KERN_CODESIGN_ERROR = 50
    KERN_POLICY_STATIC = 51
    KERN_INSUFFICIENT_BUFFER_SIZE = 52
    KERN_DENIED = 53


# osfmk/mach/port.h

class MachPortFlavor(Enum):
    MACH_PORT_LIMITS_INFO = 1
    MACH_PORT_RECEIVE_STATUS = 2
    MACH_PORT_DNREQUESTS_SIZE = 3
    MACH_PORT_TEMPOWNER = 4
    MACH_PORT_IMPORTANCE_RECEIVER = 5
    MACH_PORT_DENAP_RECEIVER = 6
    MACH_PORT_INFO_EXT = 7


# osfmk/mach/thread_switch.h

class SwitchOption(Enum):
    SWITCH_OPTION_NONE = 0
    SWITCH_OPTION_DEPRESS = 1
    SWITCH_OPTION_WAIT = 2
    SWITCH_OPTION_DISPATCH_CONTENTION = 3
    SWITCH_OPTION_OSLOCK_DEPRESS = 4
    SWITCH_OPTION_OSLOCK_WAIT = 5


# osfmk/mach/mk_timer.h

class MkTimerFlags(Enum):
    MK_TIMER_NORMAL = 0
    MK_TIMER_CRITICAL = 1


@dataclass
class KernelUncategorizedExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'KernelUncategorizedExcArm, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class KernelDataAbortSameElExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'Kernel_Data_Abort_Same_EL_Exc_ARM, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class UserSvc64ExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'User_SVC64_Exc_ARM, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class Interrupt:
    ktraces: List
    pc: int
    is_user: bool
    type: int

    def __str__(self):
        return f'INTERRUPT, pc: {hex(self.pc)}, is_user: {self.is_user}, type: {InterruptType(self.type).name}'


@dataclass
class UserInstrAbortLowerElExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'User_Instr_Abort_Lower_EL_Exc_ARM, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class UserDataAbortLowerElExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'User_Data_Abort_Lower_EL_Exc_ARM, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class DecrTrap:
    ktraces: List
    latency: int
    pc: int
    user_mode: bool

    def __str__(self):
        return f'DecrTrap, latency: {self.latency}, pc: {hex(self.pc)}, user_mode: {self.user_mode}'


@dataclass
class DecrSet:
    ktraces: List
    decr: int
    deadline: int
    queue_count: int

    def __str__(self):
        return f'DecrSet, decr: {self.decr}'


@dataclass
class MachVmAllocate:
    ktraces: List
    target: int
    address: int
    size: int
    flags: int

    def __str__(self):
        return f'mach_vm_allocate({self.target}, {hex(self.address)}, {hex(self.size)}, {hex(self.flags)})'


@dataclass
class MachVmPurgableControl:
    ktraces: List
    target: int
    address: int
    control: int
    state: int

    def __str__(self):
        return f'mach_vm_purgable_control({self.target}, {hex(self.address)}, {self.control}, {hex(self.state)})'


@dataclass
class MachVmDeallocate:
    ktraces: List
    target: int
    address: int
    size: int

    def __str__(self):
        return f'mach_vm_deallocate({self.target}, {hex(self.address)}, {hex(self.size)})'


@dataclass
class MachVmProtect:
    ktraces: List
    target: int
    address: int
    size: int
    set_maximum: bool

    def __str__(self):
        return f'mach_vm_protect({self.target}, {hex(self.address)}, {hex(self.size)}, {str(self.set_maximum).lower()})'


@dataclass
class MachVmMap:
    ktraces: List
    target: int
    address: int
    size: int
    mask: int

    def __str__(self):
        return f'mach_vm_map({self.target}, {hex(self.address)}, {hex(self.size)}, {hex(self.mask)})'


@dataclass
class MachPortAllocate:
    ktraces: List
    target: int
    right: MachPortRight
    name: int

    def __str__(self):
        return f'mach_port_allocate({self.target}, {self.right.name}, {hex(self.name)})'


@dataclass
class MachPortDeallocate:
    ktraces: List
    target: int
    name: int

    def __str__(self):
        return f'mach_port_deallocate({self.target}, {hex(self.name)})'


@dataclass
class MachPortModRefs:
    ktraces: List
    target: int
    name: int
    right: MachPortRight
    delta: int

    def __str__(self):
        return f'mach_port_mod_refs({self.target}, {hex(self.name)}, {self.right.name}, {hex(self.delta)})'


@dataclass
class MachPortInsertRight:
    ktraces: List
    target: int
    name: int
    poly: int
    poly_poly: MachMsgTypeName

    def __str__(self):
        return f'mach_port_insert_right({self.target}, {hex(self.name)}, {hex(self.poly)}, {self.poly_poly.name})'


@dataclass
class MachPortInsertMember:
    ktraces: List
    target: int
    name: int
    pset: int

    def __str__(self):
        return f'mach_port_insert_member({self.target}, {hex(self.name)}, {hex(self.pset)})'


@dataclass
class MachPortExtractMember:
    ktraces: List
    target: int
    name: int
    pset: int

    def __str__(self):
        return f'mach_port_extract_member({self.target}, {hex(self.name)}, {hex(self.pset)})'


@dataclass
class MachPortConstruct:
    ktraces: List
    target: int
    options: int
    context: int
    name: int

    def __str__(self):
        return f'mach_port_construct({self.target}, {hex(self.options)}, {hex(self.context)}, {hex(self.name)})'


@dataclass
class MachPortDestruct:
    ktraces: List
    target: int
    name: int
    srdelta: int
    guard: int

    def __str__(self):
        return f'mach_port_destruct({self.target}, {hex(self.name)}, {hex(self.srdelta)}, {hex(self.guard)})'


@dataclass
class MachReplyPort:
    ktraces: List
    result: int

    def __str__(self):
        return f'mach_reply_port(), result: {hex(self.result)}'


@dataclass
class MachThreadSelf:
    ktraces: List
    result: int

    def __str__(self):
        return f'mach_thread_self(), result: {hex(self.result)}'


@dataclass
class TaskSelf:
    ktraces: List
    result: int

    def __str__(self):
        return f'task_self(), result: {self.result}'


@dataclass
class HostSelf:
    ktraces: List
    result: int

    def __str__(self):
        return f'host_self(), result: {hex(self.result)}'


@dataclass
class SemaphoreSignal:
    ktraces: List
    signal_name: int

    def __str__(self):
        return f'semaphore_signal({hex(self.signal_name)})'


@dataclass
class SemaphoreWait:
    ktraces: List
    wait_name: int

    def __str__(self):
        return f'semaphore_wait({hex(self.wait_name)})'


@dataclass
class SemaphoreTimedwait:
    ktraces: List
    wait_name: int
    sec: int
    nsec: int
    result: KernReturn

    def __str__(self):
        return f'semaphore_timedwait({hex(self.wait_name)}, {self.sec}, {self.nsec}), result: {self.result.name}'


@dataclass
class MachPortGetAttributes:
    ktraces: List
    target: int
    name: int
    flavor: MachPortFlavor
    port_info_out: int

    def __str__(self):
        return (f'mach_port_get_attributes({self.target}, {hex(self.name)}, {self.flavor.name}, '
                f'{hex(self.port_info_out)})')


@dataclass
class MachPortGuard:
    ktraces: List
    target: int
    name: int
    guard: int
    strict: bool

    def __str__(self):
        return f'mach_port_guard({self.target}, {hex(self.name)}, {hex(self.guard)}, {str(self.strict).lower()})'


@dataclass
class MachPortUnguard:
    ktraces: List
    target: int
    name: int
    guard: int

    def __str__(self):
        return f'mach_port_unguard({self.target}, {hex(self.name)}, {hex(self.guard)})'


@dataclass
class MachGenerateActivityId:
    ktraces: List
    target: int
    count: int
    activity_id: int

    def __str__(self):
        return f'mach_generate_activity_id({self.target}, {self.count}, {hex(self.activity_id)})'


@dataclass
class MachMsg2:
    ktraces: List
    data: int
    option64: int
    header: int
    send_size: int

    def __str__(self):
        return f'mach_msg2({hex(self.data)}, {hex(self.option64)}, {hex(self.header)}, {hex(self.send_size)})'


@dataclass
class ThreadGetSpecialReplyPort:
    ktraces: List
    result: int

    def __str__(self):
        return f'thread_get_special_reply_port(), result {hex(self.result)}'


@dataclass
class ThreadSwitch:
    ktraces: List
    thread_name: int
    option: SwitchOption
    option_time: int

    def __str__(self):
        return f'thread_switch({hex(self.thread_name)}, {self.option.name}, {self.option_time})'


@dataclass
class HostCreateMachVoucher:
    ktraces: List
    host: int
    recipes: int
    recipes_size: int
    voucher: int

    def __str__(self):
        return (f'host_create_mach_voucher({hex(self.host)}, {hex(self.recipes)}, {self.recipes_size}'
                f', {hex(self.voucher)})')


@dataclass
class MachPortType:
    ktraces: List
    task: int
    name: int
    ptype: int

    def __str__(self):
        return f'mach_port_type({self.task}, {hex(self.name)}, {hex(self.ptype)})'


@dataclass
class MachPortRequestNotification:
    ktraces: List
    task: int
    name: int
    msgid: int
    sync: int

    def __str__(self):
        return f'mach_port_request_notification({self.task}, {hex(self.name)}, {hex(self.msgid)}, {self.sync})'


@dataclass
class MachTimebaseInfo:
    ktraces: List
    info: int

    def __str__(self):
        return f'mach_timebase_info({hex(self.info)})'


@dataclass
class MachWaitUntil:
    ktraces: List
    deadline: int

    def __str__(self):
        return f'mach_wait_until({self.deadline})'


@dataclass
class MkTimerCreate:
    ktraces: List
    timer_port: int

    def __str__(self):
        return f'mk_timer_create(), timer: {hex(self.timer_port)}'


@dataclass
class MkTimerDestroy:
    ktraces: List
    name: int

    def __str__(self):
        return f'mk_timer_destroy({hex(self.name)})'


@dataclass
class MkTimerArm:
    ktraces: List
    name: int
    expire_time: int

    def __str__(self):
        return f'mk_timer_arm({hex(self.name)}, {self.expire_time})'


@dataclass
class MkTimerCancel:
    ktraces: List
    name: int
    result_time: int

    def __str__(self):
        return f'mk_timer_cancel({hex(self.name)}, {self.result_time})'


@dataclass
class MkTimerArmLeeway:
    ktraces: List
    name: int
    mk_timer_flags: MkTimerFlags
    mk_timer_expire_time: int
    mk_timer_leeway: int

    def __str__(self):
        return (f'mk_timer_arm_leeway({hex(self.name)}, {self.mk_timer_flags.name}, {self.mk_timer_expire_time}'
                f', {self.mk_timer_leeway})')


@dataclass
class IokitUserClient:
    ktraces: List
    user_client_ref: int
    index: int
    p1: int
    p2: int

    def __str__(self):
        return f'iokit_user_client({hex(self.user_client_ref)}, {self.index}, {hex(self.p1)}, {hex(self.p2)})'


@dataclass
class ThreadSetVoucher:
    ktraces: List
    tid: int
    port: int
    voucher: int
    persona_id: int

    def __str__(self):
        return (f'thread_set_voucher, tid: {self.tid}, port: {hex(self.port)}, voucher: {hex(self.voucher)}, '
                f'persona_id: {self.persona_id}')


@dataclass
class MachPageout:
    ktraces: List
    size: int

    def __str__(self):
        return f'MACH_Pageout, size: {hex(self.size)}'


@dataclass
class MachVmfault:
    ktraces: List
    addr: int
    is_kernel: bool
    result: int
    fault_type: DbgVmFaultType = None
    pid: int = None
    caller_prot: List = None

    def __str__(self):
        ret = f'MachVmfault, addr: {hex(self.addr)}, is_kernel: {self.is_kernel}, result: {self.result}'
        if self.result == 0:
            ret += f', type: {self.fault_type.name}'
            if self.pid is not None and self.caller_prot is not None:
                prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
                ret += f', vm_prot: {prot}, pid: {self.pid}'
        return ret


@dataclass
class RealFaultAddressInternal:
    ktraces: List
    vaddr: int
    user_tag: int
    caller_prot: List
    fault_type: DbgVmFaultType
    offset: int
    pid: int

    def __str__(self):
        prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
        return (f'RealFaultAddressInternal, vaddr: {hex(self.vaddr)},'
                f' vm_prot: {prot}, type: {self.fault_type.name}, pid: {self.pid}')


@dataclass
class RealFaultAddressExternal:
    ktraces: List
    vaddr: int
    user_tag: int
    caller_prot: List
    fault_type: DbgVmFaultType
    offset: int
    pid: int

    def __str__(self):
        prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
        return (f'RealFaultAddressExternal, vaddr: {hex(self.vaddr)},'
                f' vm_prot: {prot}, type: {self.fault_type.name}, pid: {self.pid}')


@dataclass
class RealFaultAddressSharedCache:
    ktraces: List
    vaddr: int
    user_tag: int
    caller_prot: List
    fault_type: DbgVmFaultType
    offset: int
    pid: int

    def __str__(self):
        prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
        return (f'RealFaultAddressSharedCache, vaddr: {hex(self.vaddr)},'
                f' vm_prot: {prot}, type: {self.fault_type.name}, pid: {self.pid}')


@dataclass
class MachSched:
    ktraces: List
    reason: List[AsynchronousSystemTrapsReason]
    to: int
    from_sched_pri: int
    to_sched_pri: int

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        return f'MACH_SCHED, to: {self.to}, reason: {reason}'


@dataclass
class MachStkhandoff:
    ktraces: List
    from_: int
    to: int
    reason: List[AsynchronousSystemTrapsReason]
    from_sched_pri: int
    to_sched_pri: int

    def __str__(self):
        return f'stack_handoff({self.from_}, {self.to})'


@dataclass
class MachMkrunnable:
    ktraces: List
    tid: int
    sched_pri: int
    wait_result: int
    runnable_threads: int

    def __str__(self):
        return f'MACH_MKRUNNABLE, tid: {self.tid}, wait_result: {self.wait_result}'


@dataclass
class MachIdle:
    ktraces: List
    from_: int
    process_state: ProcessState
    to: int
    reason: List

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        return f'MACH_IDLE, from: {self.from_}, to: {self.to}, reason: {reason}, state: {self.process_state.name}'


@dataclass
class MachBlock:
    ktraces: List
    reason: List[AsynchronousSystemTrapsReason]
    continuation: int

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        return f'MACH_BLOCK, reason: {reason}, continuation: {hex(self.continuation)}'


@dataclass
class MachWait:
    ktraces: List
    event: int

    def __str__(self):
        return f'MACH_WAIT, event: {hex(self.event)}'


@dataclass
class MachDispatch:
    ktraces: List
    tid: int
    reason: List
    state: List
    runnable_threads: int

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        state = ' | '.join(map(lambda s: s.name, self.state))
        return f'MACH_DISPATCH, tid: {self.tid}, reason: {reason}, state: {state}'


@dataclass
class ThreadGroupSet:
    ktraces: List
    current_tgid: int
    target_tgid: int
    tid: int
    home_tgid: int

    def __str__(self):
        return (f'THREAD_GROUP_SET, from: {self.current_tgid}, to: {self.target_tgid}, '
                f'tid: {self.tid}, home: {self.home_tgid}')


@dataclass
class SchedClutchCpuThreadSelect:
    ktraces: List
    tid: int
    tgid: int
    scb_bucket: int

    def __str__(self):
        return f'SCHED_CLUTCH_CPU_THREAD_SELECT, tid: {self.tid}'


@dataclass
class SchedClutchTgBucketPri:
    ktraces: List
    tgid: int
    scb_bucket: int
    priority: int
    interactive_score: int

    def __str__(self):
        return f'SCHED_CLUTCH_TG_BUCKET_PRI, tgid: {self.tgid}, bucket: {self.scb_bucket}, priority: {self.priority}'


def handle_kernel_uncategorized_exc_arm(parser, events):
    return KernelUncategorizedExcArm(events, *events[0].values[:3])


def handle_kernel_data_abort_same_el_exc_arm(parser, events):
    return KernelDataAbortSameElExcArm(events, *events[0].values[:3])


def handle_user_svc64_exc_arm(parser, events):
    return UserSvc64ExcArm(events, *events[0].values[:3])


def handle_user_instr_abort_lower_el_exc_arm(parser, events):
    return UserInstrAbortLowerElExcArm(events, *events[0].values[:3])


def handle_user_data_abort_lower_el_exc_arm(parser, events):
    args = events[0].values
    return UserDataAbortLowerElExcArm(events, args[0], args[1], args[2])


def handle_interrupt(parser, events):
    args = events[0].values
    return Interrupt(events, args[1], bool(args[2]), args[3])


def handle_decr_trap(parser, events):
    args = events[0].values
    return DecrTrap(events, ctypes.c_int64(args[0]).value, args[1], bool(args[2]))


def handle_decr_set(parser, events):
    args = events[0].values
    return DecrSet(events, args[0], args[2], args[3])


def handle_msc_mach_vm_allocate_trap(parser, events):
    return MachVmAllocate(events, *events[0].values)


def handle_msc_kern_mach_vm_purgable_control_trap(parser, events):
    return MachVmPurgableControl(events, *events[0].values)


def handle_msc_mach_vm_deallocate_trap(parser, events):
    return MachVmDeallocate(events, *events[0].values[:3])


def handle_msc_mach_vm_protect_trap(parser, events):
    return MachVmProtect(events, *events[0].values[:3], bool(events[0].values[3]))


def handle_msc_mach_vm_map_trap(parser, events):
    return MachVmMap(events, *events[0].values)


def handle_msc_mach_port_allocate_trap(parser, events):
    args = events[0].values
    return MachPortAllocate(events, args[0], MachPortRight(args[1]), args[2])


def handle_msc_mach_port_deallocate_trap(parser, events):
    return MachPortDeallocate(events, *events[0].values[:2])


def handle_msc_mach_port_mod_refs_trap(parser, events):
    args = events[0].values
    return MachPortModRefs(events, args[0], args[1], MachPortRight(args[2]), args[3])


def handle_msc_mach_port_insert_right_trap(parser, events):
    return MachPortInsertRight(events, *events[0].values[:3], MachMsgTypeName(events[0].values[3]))


def handle_msc_mach_port_insert_member_trap(parser, events):
    return MachPortInsertMember(events, *events[0].values[:3])


def handle_msc_mach_port_extract_member_trap(parser, events):
    return MachPortExtractMember(events, *events[0].values[:3])


def handle_msc_mach_port_construct_trap(parser, events):
    return MachPortConstruct(events, *events[0].values)


def handle_msc_mach_port_destruct_trap(parser, events):
    return MachPortDestruct(events, *events[0].values)


def handle_msc_mach_reply_port(parser, events):
    return MachReplyPort(events, events[-1].values[0])


def handle_msc_thread_self_trap(parser, events):
    return MachThreadSelf(events, events[-1].values[0])


def handle_msc_task_self_port(parser, events):
    return TaskSelf(events, events[-1].values[0])


def handle_msc_host_self_port(parser, events):
    return HostSelf(events, events[-1].values[0])


def handle_msc_semaphore_signal_trap(parser, events):
    return SemaphoreSignal(events, events[0].values[0])


def handle_msc_semaphore_wait_trap(parser, events):
    return SemaphoreWait(events, events[0].values[0])


def handle_msc_semaphore_timedwait_trap(parser, events):
    args = events[0].values
    return SemaphoreTimedwait(events, args[0], args[1] & 0xffffffff, args[2], KernReturn(events[-1].values[0]))


def handle_msc_mach_port_get_attributes_trap(parser, events):
    args = events[0].values
    return MachPortGetAttributes(events, *args[:2], MachPortFlavor(args[2]), args[3])


def handle_msc_mach_port_guard_trap(parser, events):
    return MachPortGuard(events, *events[0].values[:3], bool(events[0].values[3]))


def handle_msc_mach_port_unguard_trap(parser, events):
    return MachPortUnguard(events, *events[0].values[:3])


def handle_msc_mach_generate_activity_id(parser, events):
    return MachGenerateActivityId(events, *events[0].values[:3])


def handle_msc_mach_msg2_trap(parser, events):
    return MachMsg2(events, *events[0].values)


def handle_msc_thread_get_special_reply_port(parser, events):
    return ThreadGetSpecialReplyPort(events, events[-1].values[0])


def handle_msc_thread_switch(parser, events):
    args = events[0].values
    return ThreadSwitch(events, args[0], SwitchOption(args[1]), args[2])


def handle_msc_host_create_mach_voucher_trap(parser, events):
    return HostCreateMachVoucher(events, *events[0].values)


def handle_msc_mach_port_type_trap(parser, events):
    return MachPortType(events, *events[0].values[:3])


def handle_msc_mach_port_request_notification_trap(parser, events):
    return MachPortRequestNotification(events, *events[0].values)


def handle_msc_mach_timebase_info(parser, events):
    return MachTimebaseInfo(events, events[0].values[0])


def handle_msc_mach_wait_until(parser, events):
    return MachWaitUntil(events, events[0].values[0])


def handle_msc_mk_timer_create(parser, events):
    return MkTimerCreate(events, events[-1].values[0])


def handle_msc_mk_timer_destroy(parser, events):
    return MkTimerDestroy(events, events[0].values[0])


def handle_msc_mk_timer_arm(parser, events):
    return MkTimerArm(events, *events[0].values[:2])


def handle_msc_mk_timer_cancel(parser, events):
    return MkTimerCancel(events, *events[0].values[:2])


def handle_msc_mk_timer_arm_leeway(parser, events):
    args = events[0].values
    return MkTimerArmLeeway(events, args[0], MkTimerFlags(args[1]), args[2], args[3])


def handle_msc_iokit_user_client(parser, events):
    return IokitUserClient(events, *events[0].values)


def handle_mach_thread_set_voucher(parser, events):
    return ThreadSetVoucher(events, *events[0].values)


def handle_mach_pageout(parser, events):
    return MachPageout(events, events[0].values[0])


def handle_mach_vmfault(parser, events):
    args = events[0].values
    is_kernel = bool(args[2])
    rets = events[-1].values
    result = rets[2]
    fault_type = None
    pid = None
    caller_prot = None
    if result == 0:
        fault_type = DbgVmFaultType(rets[3])
        real_events = [e for e in events[1:-1] if 0x1320008 <= e.eventid <= 0x1320014]
        if real_events:
            vm_fault_real = parser.parse_event_list(real_events)
            pid = vm_fault_real.pid
            caller_prot = vm_fault_real.caller_prot
    return MachVmfault(events, args[1], is_kernel, result, fault_type, pid, caller_prot)


def handle_real_fault_address(addr_type, parser, events):
    args = events[0].values
    caller_prot = to_vm_prot((args[1] >> 8) & 0xff)
    fault_type = DbgVmFaultType(args[1] & 0xff)
    return addr_type(events, args[0], args[1] >> 16, caller_prot, fault_type, args[2], args[3])


def handle_mach_sched(parser, events):
    args = events[0].values
    return MachSched(events, to_ast_reasons(args[0]), args[1], args[2], args[3])


def handle_mach_stkhandoff(parser, events):
    args = events[0].values
    return MachStkhandoff(events, events[0].tid, args[1], to_ast_reasons(args[0]), args[2], args[3])


def handle_mach_mkrunnable(parser, events):
    args = events[0].values
    return MachMkrunnable(events, args[0], args[1], args[2], args[3])


def handle_mach_idle(parser, events):
    args = events[-1].values
    return MachIdle(events, args[0], ProcessState(args[1]), args[2], to_ast_reasons(args[3]))


def handle_mach_block(parser, events):
    args = events[0].values
    return MachBlock(events, to_ast_reasons(args[0]), args[1])


def handle_mach_wait(parser, events):
    return MachWait(events, events[0].values[0])


def handle_mach_dispatch(parser, events):
    args = events[0].values
    return MachDispatch(events, args[0], to_ast_reasons(args[1]), to_thread_state(args[2]), args[3])


def handle_thread_group_set(parser, events):
    args = events[0].values
    return ThreadGroupSet(events, ctypes.c_int64(args[0]).value, args[1], args[2], args[3])


def handle_sched_clutch_cpu_thread_select(parser, events):
    args = events[0].values
    return SchedClutchCpuThreadSelect(events, args[0], args[1], args[2])


def handle_sched_clutch_tg_bucket_pri(parser, events):
    args = events[0].values
    return SchedClutchTgBucketPri(events, args[0], args[1], args[2], args[3])


handlers = {
    'Kernel_Uncategorized_Exc_ARM': handle_kernel_uncategorized_exc_arm,
    'Kernel_Data_Abort_Same_EL_Exc_ARM': handle_kernel_data_abort_same_el_exc_arm,
    'User_SVC64_Exc_ARM': handle_user_svc64_exc_arm,
    'User_Instr_Abort_Lower_EL_Exc_ARM': handle_user_instr_abort_lower_el_exc_arm,
    'User_Data_Abort_Lower_EL_Exc_ARM': handle_user_data_abort_lower_el_exc_arm,
    'INTERRUPT': handle_interrupt,
    'DecrTrap': handle_decr_trap,
    'DecrSet': handle_decr_set,
    'MSC_mach_vm_allocate_trap': handle_msc_mach_vm_allocate_trap,
    'MSC_kern_mach_vm_purgable_control_trap': handle_msc_kern_mach_vm_purgable_control_trap,
    'MSC_mach_vm_deallocate_trap': handle_msc_mach_vm_deallocate_trap,
    'MSC_mach_vm_protect_trap': handle_msc_mach_vm_protect_trap,
    'MSC_mach_vm_map_trap': handle_msc_mach_vm_map_trap,
    'MSC_mach_port_allocate_trap': handle_msc_mach_port_allocate_trap,
    'MSC_mach_port_deallocate_trap': handle_msc_mach_port_deallocate_trap,
    'MSC_mach_port_mod_refs_trap': handle_msc_mach_port_mod_refs_trap,
    'MSC_mach_port_insert_right_trap': handle_msc_mach_port_insert_right_trap,
    'MSC_mach_port_insert_member_trap': handle_msc_mach_port_insert_member_trap,
    'MSC_mach_port_extract_member_trap': handle_msc_mach_port_extract_member_trap,
    'MSC_mach_port_construct_trap': handle_msc_mach_port_construct_trap,
    'MSC_mach_port_destruct_trap': handle_msc_mach_port_destruct_trap,
    'MSC_mach_reply_port': handle_msc_mach_reply_port,
    'MSC_thread_self_trap': handle_msc_thread_self_trap,
    'MSC_task_self_trap': handle_msc_task_self_port,
    'MSC_host_self_trap': handle_msc_host_self_port,
    'MSC_semaphore_signal_trap': handle_msc_semaphore_signal_trap,
    'MSC_semaphore_wait_trap': handle_msc_semaphore_wait_trap,
    'MSC_semaphore_timedwait_trap': handle_msc_semaphore_timedwait_trap,
    'MSC_mach_port_get_attributes_trap': handle_msc_mach_port_get_attributes_trap,
    'MSC_mach_port_guard_trap': handle_msc_mach_port_guard_trap,
    'MSC_mach_port_unguard_trap': handle_msc_mach_port_unguard_trap,
    'MSC_mach_generate_activity_id': handle_msc_mach_generate_activity_id,
    'MSC_mach_msg2_trap': handle_msc_mach_msg2_trap,
    'MSC_thread_get_special_reply_port': handle_msc_thread_get_special_reply_port,
    'MSC_thread_switch': handle_msc_thread_switch,
    'MSC_host_create_mach_voucher_trap': handle_msc_host_create_mach_voucher_trap,
    'MSC_mach_port_type_trap': handle_msc_mach_port_type_trap,
    'MSC_mach_port_request_notification_trap': handle_msc_mach_port_request_notification_trap,
    'MSC_mach_timebase_info': handle_msc_mach_timebase_info,
    'MSC_mach_wait_until': handle_msc_mach_wait_until,
    'MSC_mk_timer_create': handle_msc_mk_timer_create,
    'MSC_mk_timer_destroy': handle_msc_mk_timer_destroy,
    'MSC_mk_timer_arm': handle_msc_mk_timer_arm,
    'MSC_mk_timer_cancel': handle_msc_mk_timer_cancel,
    'MSC_mk_timer_arm_leeway': handle_msc_mk_timer_arm_leeway,
    'MSC_iokit_user_client': handle_msc_iokit_user_client,
    'MACH_thread_set_voucher': handle_mach_thread_set_voucher,
    'MACH_Pageout': handle_mach_pageout,
    'MACH_vmfault': handle_mach_vmfault,
    'RealFaultAddressInternal': partial(handle_real_fault_address, RealFaultAddressInternal),
    'RealFaultAddressExternal': partial(handle_real_fault_address, RealFaultAddressExternal),
    'RealFaultAddressSharedCache': partial(handle_real_fault_address, RealFaultAddressSharedCache),
    'MACH_SCHED': handle_mach_sched,
    'MACH_STKHANDOFF': handle_mach_stkhandoff,
    'MACH_MKRUNNABLE': handle_mach_mkrunnable,
    'MACH_IDLE': handle_mach_idle,
    'MACH_BLOCK': handle_mach_block,
    'MACH_WAIT': handle_mach_wait,
    'MACH_DISPATCH': handle_mach_dispatch,
    'THREAD_GROUP_SET': handle_thread_group_set,
    'SCHED_CLUTCH_CPU_THREAD_SELECT': handle_sched_clutch_cpu_thread_select,
    'SCHED_CLUTCH_TG_BUCKET_PRI': handle_sched_clutch_tg_bucket_pri,
}
