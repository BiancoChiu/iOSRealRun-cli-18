from typing import Optional

from la_panic.data_structure.raw_crash_stack import RawCrashStack, ReachedEndOfStack
from la_panic.panic_parser.backtrace import Backtrace
from la_panic.panic_parser.kernel_panic_full_type import KernelPanicFullType
from la_panic.panic_parser.kext import LoadedKextInfo
from la_panic.panic_parser.panic_specific.kernel_specific_base import KernelSpecificBase, KernelSpecificPanic


class KernelFullPanicAdditionalInfo(KernelSpecificBase, KernelSpecificPanic):
    __kext_info: Optional[LoadedKextInfo] = None
    __backtrace: Optional[Backtrace] = None
    __kernel_full_panic_specific: str

    def __init__(self, data: str):
        panic_infos = RawCrashStack(data)
        try:
            additional_info_lines = panic_infos.pop_until_line_containing("OS release type")
        except ReachedEndOfStack as e:
            # probably an undefined panic. Lets try to simply read it as a string
            self.__kernel_full_panic_specific = "\n".join(e.read_stack)
            return

        super().__init__(panic_infos)
        self.__backtrace = Backtrace(panic_infos, "last started kext")
        self.__kext_info = LoadedKextInfo(panic_infos)

        self.parse_additional_info(additional_info_lines)

    @property
    def backtrace(self) -> Backtrace:
        return self.__backtrace

    @property
    def kext_info(self) -> LoadedKextInfo:
        return self.__kext_info

    @property
    def description(self) -> str:
        return self.__kernel_full_panic_specific

    def parse_additional_info(self, additional_info_lines: [str]):
        # pop panic(cpu <number> caller <address>) string
        line_containing_kernel_full_panic_subtype = additional_info_lines[0].split(": ", 1)[1]

        for kernel_full_panic_subtype in KernelPanicFullType:
            if line_containing_kernel_full_panic_subtype.startswith(kernel_full_panic_subtype.value):
                self.__kernel_full_panic_specific \
                    = kernel_full_panic_subtype.parse_kernel_panic_additional_info(additional_info_lines[1:])
                return

        # Unknown type. Lets try to handle this as a general string
        self.__kernel_full_panic_specific = "\n".join(additional_info_lines[1:])
