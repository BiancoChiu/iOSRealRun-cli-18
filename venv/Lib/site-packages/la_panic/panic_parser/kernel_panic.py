import json
import click
from datetime import datetime
from typing import Mapping, Any, Optional, List

from la_panic.panic_parser.backtrace import Backtrace
from la_panic.panic_parser.bug_type import BugType
from la_panic.panic_parser.core_state.core_state import CoreInfo
from la_panic.panic_parser.exception import LaPanicException
from la_panic.panic_parser.memory_status import MemoryStatus
from la_panic.panic_parser.panic_specific.kernel_force_reset_panic import KernelForceResetAdditionalInfo
from la_panic.panic_parser.panic_specific.kernel_full_panic import KernelFullPanicAdditionalInfo
from la_panic.panic_parser.kext import LoadedKextInfo
from la_panic.panic_parser.panic_specific.kernel_specific_base import KernelSpecificPanic
from la_panic.panic_parser.process_list import ProcessList
from la_panic.panic_parser.sliders import KernelSliders
from la_panic.panic_parser.socd_container import SOCDContainer
from la_panic.panic_parser.versions import KernelPanicVersions, KernelVersion, MetadataIOSVersion
from la_panic.utilities.apple_date_time import AppleDateTime
from la_panic.utilities.device_types import iPhoneModels
from la_panic.utilities.device_types import iPhoneModel


class UnsupportedBugTypeException(LaPanicException):
    pass


class KernelPanicMetadata(object):
    __raw_json: object
    __bug_type: BugType
    __timestamp: datetime
    __os_version: MetadataIOSVersion

    def __init__(self, metadata: Mapping[str, Any]):
        try:
            self.__bug_type = BugType(metadata["bug_type"])
        except ValueError:
            raise UnsupportedBugTypeException(f"Type = {metadata['bug_type']}")

        self.__timestamp = AppleDateTime.datetime(metadata["timestamp"])
        self.__os_version = MetadataIOSVersion(metadata['os_version'])

        self.__raw_json = metadata

    @property
    def bug_type(self) -> BugType:
        return self.__bug_type

    @property
    def os_version(self) -> MetadataIOSVersion:
        return self.__os_version


class ExtendedKernelPanic(object):
    __raw_json: Mapping[str, Any]

    __os_version: MetadataIOSVersion
    __model: iPhoneModel
    __socId: int
    __bug_type: BugType
    __incident_id: str
    __timestamp: datetime
    __kernel: KernelVersion
    __panic_flags: str
    __additional_info: KernelSpecificPanic
    __memory_status: MemoryStatus
    __process_list: ProcessList
    __socd_containers: List[SOCDContainer] = []
    __foreground_app_hash: Optional[str] = None

    def __init__(self, data: str):
        raw_json = json.loads(data)

        self.__raw_json = raw_json
        self.__os_version = MetadataIOSVersion(raw_json['build'])
        self.__model = iPhoneModels().get_model(raw_json['product'])
        self.__socId = int(raw_json['socId'], 16)
        self.__kernel = KernelVersion(raw_json['kernel'])
        self.__incident_id = raw_json['incident']
        self.__timestamp = AppleDateTime.datetime(raw_json['date'])
        self.__panic_flags = raw_json['panicFlags']

        if raw_json.get('memoryStatus'):
            self.__memory_status = MemoryStatus(raw_json['memoryStatus'])
        if raw_json.get('processByPid'):
            self.__process_list = ProcessList(raw_json['processByPid'])

        try:
            self.__bug_type = BugType(raw_json["bug_type"])
        except ValueError:
            raise UnsupportedBugTypeException(f"Type = {raw_json['bug_type']}")

        if raw_json.get('SOCDContainers'):
            for socd_container_raw in raw_json['SOCDContainers']:
                socd_container = SOCDContainer(socd_container_raw)
                self.__socd_containers.append(socd_container)

        if raw_json.get('foregroundAppHash'):
            self.__foreground_app_hash = hex(int(raw_json['foregroundAppHash'], 16))

        self.__additional_info = ExtendedKernelPanic.create_additional_info(self.__bug_type, raw_json)

    @staticmethod
    def create_additional_info(bug_type: BugType, raw_json: Mapping[str, Any]):
        if bug_type == BugType.FULL:
            return KernelFullPanicAdditionalInfo(raw_json['panicString'])
        elif bug_type == BugType.FORCE_RESET:
            return KernelForceResetAdditionalInfo(raw_json['string'])

    @property
    def json(self) -> str:
        return f"\"timestamp\": \"{self.__timestamp}\",\n\
    \"os_version\": \"{self.__os_version.version}\",\n\
    \"model\" : \"{self.model.name}\",\n\
    \"xnu\": \"{self.kernel.xnu}\",\n\
    \"sliders\": {self.sliders},\n\
    \"backtrace\": {self.backtrace},\n\
    \"crashed_core\": {self.crashed_core},\n\
    \"kext\": {self.kext_info}"""

    @property
    def kernel(self) -> KernelVersion:
        return self.__kernel

    @property
    def model(self) -> iPhoneModel:
        return self.__model

    @property
    def backtrace(self) -> Backtrace:
        return self.__additional_info.backtrace

    @property
    def sliders(self) -> KernelSliders:
        return self.__additional_info.sliders

    @property
    def versions(self) -> KernelPanicVersions:
        return self.__additional_info.versions

    @property
    def kext_info(self) -> LoadedKextInfo:
        return self.__additional_info.kext_info

    @property
    def incident_id(self) -> str:
        return self.__incident_id

    @property
    def timestamp(self) -> datetime:
        return self.__timestamp

    @property
    def additional_info_description(self) -> str:
        return self.__additional_info.description

    @property
    def socd_containers(self) -> List[SOCDContainer]:
        return self.__socd_containers

    @property
    def foreground_application_hash(self) -> hex:
        return self.__foreground_app_hash

    @property
    def cores_state(self) -> List[CoreInfo]:
        return self.__additional_info.cores_state


class KernelPanic(object):
    __metadata: KernelPanicMetadata
    __panic: ExtendedKernelPanic
    __filename: str

    def __init__(self, metadata: Mapping[str, Any], panic_data: str, filename: str):
        self.__filename = filename
        self.__metadata = KernelPanicMetadata(metadata)
        self.__panic = ExtendedKernelPanic(panic_data)

    @property
    def bug_type(self):
        return self.__metadata.bug_type

    @property
    def os_version(self) -> str:
        return self.__metadata.os_version.version

    @property
    def timestamp(self):
        return self.__panic.timestamp

    @property
    def incident_id(self):
        return self.__panic.incident_id

    @property
    def xnu(self) -> str:
        return self.__panic.kernel.xnu

    @property
    def model(self) -> iPhoneModel:
        return self.__panic.model

    @property
    def additional_info(self) -> str:
        return self.__panic.additional_info_description

    @property
    def backtrace(self) -> Backtrace:
        return self.__panic.backtrace

    @property
    def sliders(self) -> KernelSliders:
        return self.__panic.sliders

    @property
    def iboot_version(self) -> str:
        return self.__panic.versions.iboot

    @property
    def kext_info(self) -> [LoadedKextInfo]:
        return self.__panic.kext_info

    @property
    def socd_containers(self):
        return self.__panic.socd_containers

    @property
    def foreground_application_hash(self) -> hex:
        return self.__panic.foreground_application_hash

    @property
    def cores_state(self) -> List[CoreInfo]:
        return self.__panic.cores_state

    def json(self):
        return f"{{\n\
    \"bug_type\": {self.bug_type},\n\
    {self.__panic.json}\n\
    }}"

    def __repr__(self):
        description = ''
        description += click.style(f'{self.incident_id} {self.timestamp}\n{self.__filename}\n\n', fg='cyan')

        description += click.style('Exception: Panic\n', bold=True)
        description += "\n"
        description += click.style('Metadata:\n', bold=True)
        description += click.style(f'\tBug Type: {self.bug_type.name}\n')
        description += click.style(f'\tTimestamp: {self.timestamp}\n')
        description += click.style(f"\tiPhone Model: {self.model.name} ({self.model.product_type})\n")
        description += click.style(f"\tXNU Version: {self.xnu}\n")
        description += "\n\n"
        description += click.style("Additional Info:\n\n", bold=True)
        description += click.style(f"{self.additional_info}")
        description += "\n\n"
        description += click.style("Backtrace:\n", bold=True)
        description += click.style(f"{self.backtrace}")
        description += "\n\n"
        description += click.style("Sliders:\n", bold=True)
        description += click.style(f"{self.sliders}")
        description += "\n\n"
        description += click.style("Loaded kexts:\n", bold=True)
        description += click.style(f"{self.kext_info}\n\n")

        if len(self.socd_containers) > 0:
            description += click.style("SOCDContainers:\n", bold=True)
            for soc_id, socd_container in enumerate(self.socd_containers):
                description += click.style(f"\tSOC {soc_id}:\n\t{socd_container}\n\n")

        if self.foreground_application_hash:
            description += click.style("Foreground Application Hash:\n", bold=True)
            description += click.style(f"\t{self.foreground_application_hash}\n\n")

        return description

    def __str__(self):
        return self.__repr__()
