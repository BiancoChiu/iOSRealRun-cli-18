import click

from enum import Enum

from la_panic.panic_parser.core_state.crashed_core_state import CrashedCoreState


class KernelPanicFullType(Enum):
    DATA_ABORT = "Kernel data abort"
    BUSY_TIMEOUT = "busy timeout"

    def parse_kernel_panic_additional_info(self, additional_info_lines: [str]) -> str:
        additional_info = ""
        if self == KernelPanicFullType.DATA_ABORT:
            # Remove Debugger message, Message ID
            additional_info_lines = additional_info_lines[:-2]
            crashed_core_state = CrashedCoreState(additional_info_lines)
            additional_info += click.style("Crashed Core State:\n", bold=True)
            additional_info += click.style(f"{crashed_core_state}")
        elif KernelPanicFullType.BUSY_TIMEOUT:
            # Remove Debugger message, Device, Hardware model and ECID
            additional_info_lines = additional_info_lines[4:]
            additional_info += click.style("Boot args: ", bold=True)
            additional_info += click.style(additional_info_lines[0].rsplit(":", 1)[1])

        return additional_info
