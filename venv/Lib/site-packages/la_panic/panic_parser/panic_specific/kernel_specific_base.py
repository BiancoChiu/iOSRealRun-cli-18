from abc import ABC, abstractmethod
from typing import List, Optional

from la_panic.data_structure.raw_crash_stack import RawCrashStack
from la_panic.panic_parser.backtrace import Backtrace
from la_panic.panic_parser.core_state.core_state import CoreState, CoreInfo
from la_panic.panic_parser.kext import LoadedKextInfo
from la_panic.panic_parser.sliders import KernelSliders
from la_panic.panic_parser.system.system_manager import SystemDependency, SystemManager
from la_panic.panic_parser.versions import KernelPanicVersions
from la_panic.panic_parser.zone import ZoneInfo


class KernelSpecificPanic(ABC):

    @property
    @abstractmethod
    def backtrace(self) -> Backtrace:
        pass

    @property
    @abstractmethod
    def kext_info(self) -> LoadedKextInfo:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def sliders(self) -> KernelSliders:
        pass

    @property
    @abstractmethod
    def versions(self) -> KernelPanicVersions:
        pass

    @abstractmethod
    def parse_additional_info(self, panic_infos: RawCrashStack):
        pass

    @property
    @abstractmethod
    def cores_state(self) -> List[CoreInfo]:
        pass


class KernelSpecificBase(SystemDependency):
    __release_type: str
    __versions: KernelPanicVersions
    __secure_boot: bool
    __roots_installed: int
    __panic_log_version: str
    __sliders: Optional[KernelSliders] = None
    __zone_info: Optional[ZoneInfo] = None
    __cores_count = 0
    __cores_state: [CoreState] = []
    __panicked_task: str

    def __update_system_dependency(self):
        if self.__sliders:
            SystemManager.kernel_slide = self.__sliders.kernel_slide
            SystemManager.kernel_cache_slide = self.__sliders.kernel_cache_slide

        SystemManager.number_of_cores = len(self.__cores_state)

    def __init__(self, panic_infos: RawCrashStack):
        self.__release_type = panic_infos.pop_value_from_key_value_pair()
        self.__versions = KernelPanicVersions(panic_infos)
        self.__secure_boot = True if panic_infos.pop_value_from_key_value_pair() == 'YES' else False
        self.__roots_installed = int(panic_infos.pop_value_from_key_value_pair())
        self.__panic_log_version = panic_infos.pop_value_from_key_value_pair()
        self.__sliders = KernelSliders(panic_infos)

        # Remove epoch time info
        panic_infos.pop(6)

        self.__zone_info = ZoneInfo(panic_infos)
        self.__cores_state = KernelSpecificBase.parse_cores_state(panic_infos, self.__sliders.kernel_cache_slide)
        self.__compressor_info = panic_infos.pop_one()
        self.__panicked_task = panic_infos.pop_one()
        self.__panicked_thread = panic_infos.pop_one()

        self.__update_system_dependency()

    @staticmethod
    def parse_cores_state(panic_infos: RawCrashStack, kernel_slide: hex) -> List[CoreInfo]:
        cores_retired_instruction_data = KernelSpecificBase.core_retired_instruction(panic_infos)
        cores_state = []

        core_states_raw = panic_infos.pop_until_line_containing('Compressor Info')

        for core_index, core_state_raw in enumerate(core_states_raw):
            try:
                core_retired_instruction = cores_retired_instruction_data[core_index]
            except IndexError:
                core_retired_instruction = None

            core_state = CoreInfo(core_index, core_retired_instruction, core_state_raw)
            cores_state.append(core_state)

        return cores_state

    @staticmethod
    def core_retired_instruction(panic_infos: RawCrashStack) -> List[str]:
        cores_retired_instruction_data: List[str] = []

        while True:
            potential_retired_instruction_data = panic_infos.pop_one()
            if potential_retired_instruction_data.find("TPIDRx_ELy") != -1:
                break

            cores_retired_instruction_data.append(potential_retired_instruction_data)

        return cores_retired_instruction_data

    @property
    def description(self) -> str:
        return f"{list(filter(lambda core_state: core_state.crashed, self.__cores_state))[0]}"

    @property
    def sliders(self) -> KernelSliders:
        return self.__sliders

    @property
    def versions(self) -> KernelPanicVersions:
        return self.__versions

    @property
    def cores_state(self) -> List[CoreInfo]:
        return self.__cores_state
