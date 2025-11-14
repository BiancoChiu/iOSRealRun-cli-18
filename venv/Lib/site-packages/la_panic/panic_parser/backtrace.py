import click

from la_panic.data_structure.raw_crash_stack import RawCrashStack, ReachedEndOfStack
from la_panic.panic_parser.addresses.address_formater import reformat_register_value_to_fit
from la_panic.panic_parser.addresses.la_address import LaAddress
from la_panic.utilities.design_pattern.iteretable_with_last_object_signal import signal_last


class CallStackLevel(object):
    __lr: LaAddress
    __fp: LaAddress

    def __init__(self, callstack_call: str):
        callstack_call_parts = callstack_call.split(":")

        self.__lr = LaAddress(callstack_call_parts[1].strip().split(" ")[0])
        self.__fp = LaAddress(callstack_call_parts[2].strip())

    @property
    def lr(self) -> hex:
        return reformat_register_value_to_fit(self.__lr.unslide_named_address)

    @property
    def fp(self) -> hex:
        return reformat_register_value_to_fit(self.__fp.unslide_named_address)


class Backtrace(object):
    __callstack: [CallStackLevel] = []

    def __init__(self, panic_infos: RawCrashStack, termination_string: str):
        try:
            callstack_calls = panic_infos.pop_until_line_containing(termination_string)
        except ReachedEndOfStack as end_of_stack:
            callstack_calls = end_of_stack.read_stack

        for callstack_call in callstack_calls:
            try:
                if "kernel extension" in callstack_call.lower():
                    break
                call_stack_level = CallStackLevel(callstack_call)
                self.__callstack.append(call_stack_level)
            except Exception:
                print("aa")

    @property
    def callstack(self) -> [CallStackLevel]:
        return self.__callstack

    def __repr__(self):
        description = ""

        for call_stack_level in self.__callstack:
            description += click.style(f"\tLR = {call_stack_level.lr},  FP = {call_stack_level.fp}\n", fg='bright_white')

        return description

    def __str__(self):
        return self.__repr__()

    def json(self):
        description = "["

        for last_element, call_stack_level in signal_last(self.__callstack):
            new_line = f"\t  {{ \"LR\": \"{call_stack_level.lr}\", \"FP\": \"{call_stack_level.fp}\" }}"
            if not last_element:
                new_line += ","
            description = "\n".join((description, new_line))

        description = "\n".join((description, "    ]"))

        return description
