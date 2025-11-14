from la_panic.data_structure.raw_crash_stack import RawCrashStack


class MetadataIOSVersion(object):
    def __init__(self, version: str):
        version_parts = version.split(' (')

        self.__version = version_parts[0].strip()
        self.__build_identifier = version_parts[1].split(')')[0]

    @property
    def version(self) -> str:
        return self.__version

    @property
    def build(self) -> str:
        return self.__build_identifier


class KernelVersion(object):
    __version: str
    __xnu_version: str

    def __init__(self, description: str):
        description_parts = description.strip().split(":")

        self.__version = description_parts[0].split(" ")[3]
        self.__xnu_version = description_parts[4]

    def __repr__(self):
        return f"Kernel Version {self.__version}, XNU = {self.__xnu_version}"

    def __str__(self):
        return self.__repr__()

    @property
    def xnu(self) -> str:
        return self.__xnu_version


class KernelPanicVersions(object):
    __os_build_version: str
    __kernel_version: KernelVersion
    __kernel_cache_uuid: str
    __kernel_uuid: str
    __boot_session_uuid: str
    __iboot_version: str

    def __init__(self, panic_infos: RawCrashStack):
        self.__os_build_version = panic_infos.pop_value_from_key_value_pair()
        self.__kernel_version = KernelVersion(":".join(panic_infos.pop_one().split(":")[1:]))
        self.__kernel_cache_uuid = panic_infos.pop_value_from_key_value_pair()
        self.__kernel_uuid = panic_infos.pop_value_from_key_value_pair()
        self.__boot_session_uuid = panic_infos.pop_value_from_key_value_pair()
        self.__iboot_version = panic_infos.pop_value_from_key_value_pair()

    @property
    def os_build(self):
        return self.__os_build_version

    @property
    def kernel(self) -> str:
        return str(self.__kernel_version)

    @property
    def xnu(self) -> str:
        return self.__kernel_version.xnu

    @property
    def kernel_cache_uuid(self) -> str:
        return self.__kernel_cache_uuid

    @property
    def kernel_uuid(self) -> str:
        return self.__kernel_uuid

    @property
    def iboot(self) -> str:
        return self.__iboot_version
