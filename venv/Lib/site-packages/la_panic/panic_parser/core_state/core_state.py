from typing import Optional

from la_panic.utilities.design_pattern.iteretable_with_last_object_signal import signal_last
from la_panic.panic_parser.core_state.abstract_core_state import AbstractCoreState


class CoreState(AbstractCoreState):
    def __init__(self, core_state: str):
        if core_state.find("panicked") != -1:
            self.__crashed = True
            return

        self.pc = hex(int(core_state.split("PC=")[1].split(",")[0], 16))
        self.lr = hex(int(core_state.split("LR=")[1].split(",")[0], 16))
        self.fp = hex(int(core_state.split("FP=")[1].split(",")[0], 16))


class CoreInfo(object):
    __index: int
    __retired_instruction: hex
    __core_state: CoreState

    def __init__(self, core_index: int, core_retired_instruction_data: Optional[str], core_state: str):
        if core_retired_instruction_data:
            self.__retired_instruction = "0x".join(core_retired_instruction_data.split('0x')[1])

        self.__index = core_index
        self.__core_state = CoreState(core_state)

    @property
    def index(self) -> int:
        return self.__index

    @property
    def crashed(self) -> bool:
        return self.__core_state.crashed

    @property
    def state(self) -> CoreState:
        return self.__core_state

    def json(self):
        description = f"""{{\n\t"core_index": {self.__index},"""

        for last_object, register_name in signal_last(vars(self.__core_state)):
            if "crashed" in register_name:
                continue

            register_value = getattr(self.__core_state, register_name)
            new_line = f"\t\"{register_name}\": \"{register_value}\""
            if not last_object:
                new_line += ","
            description = "\n".join((description, new_line))

        description = "\n".join((description, "    }"))

        return description

    def __repr__(self):
        return f"{self.__core_state}"

    def __str__(self):
        return self.__repr__()
