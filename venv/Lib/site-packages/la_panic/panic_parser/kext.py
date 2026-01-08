import click

from collections import namedtuple
from typing import Optional

from la_panic.data_structure.raw_crash_stack import RawCrashStack, EmptyRawCrashStack
from la_panic.utilities.design_pattern.iteretable_with_last_object_signal import signal_last

KextInBacktraceDependencies = namedtuple('KextInBacktraceDependencies', 'backtraced dependencies')


class KextInfo(object):
    __name: str
    __version: str

    last_loaded: bool = False
    backtrace_info: Optional[KextInBacktraceDependencies] = None

    def __init__(self, panic_info: RawCrashStack):
        # Remove headline
        kext_info_parts = panic_info.pop_one().split("\t")
        self.__name = kext_info_parts[0]
        self.__version = kext_info_parts[1]

    @property
    def name(self):
        return self.__name

    @property
    def version(self):
        return self.__version

    def __repr__(self):
        if self.last_loaded:
            description = f"{{\n\
                  \"name\": \"{self.__name}\",\n\
                  \"version\": \"{self.__version}\",\n\
                  \"last_loaded\": true\n\
                }}"
        else:
            description = f"{{\n\
                  \"name\": \"{self.__name}\",\n\
                  \"version\": \"{self.__version}\"\n\
                }}"

        return description

    def __str__(self):
        return self.__repr__()


class LoadedKextInfo(object):
    __loaded_kexts: [KextInfo] = []
    __last_started_kext: Optional[KextInfo] = None

    def __init__(self, panic_info: RawCrashStack):
        try:
            self.__last_kext = panic_info.pop_one()
        except EmptyRawCrashStack:
            return

        # Remove headline
        panic_info.pop_one()

        self.__loaded_kexts = LoadedKextInfo.__parse_loaded_kext(panic_info)
        self.__last_started_kext = list(
            filter(lambda kext_info: kext_info.name in self.__last_kext, self.__loaded_kexts)
        )[0]
        self.__last_started_kext.last_loaded = True

    @staticmethod
    def __parse_loaded_kext(panic_info: RawCrashStack) -> [KextInfo]:
        kext_infos = []

        while True:
            try:
                kext_info = KextInfo(panic_info)
                kext_infos.append(kext_info)
            except EmptyRawCrashStack:
                break

        return kext_infos

    def json(self):
        description = "{{\n\t  \"loaded_kexts\": ["

        for last_object, loaded_kext in signal_last(self.__loaded_kexts):
            description = "\n\t\t".join((description, f"{loaded_kext}"))
            if not last_object:
                description += ","

        description = "\n\t  ".join((description, "]"))
        description = "\n\t".join((description, "}"))

        return description

    def __repr__(self):
        description = ""

        if self.__last_started_kext:
            description += click.style(f'\tLast selected kext:\n\t\tname = {self.__last_started_kext.name}\n\n')
        else:
            description += click.style('\tLast selected kext:\n\t\tname = None\n\n')

        description += click.style('\tKexts:\n')
        for kext_info in self.__loaded_kexts:
            description += click.style(f'\t\t{kext_info.name}, {kext_info.version}\n')

        return description

    def __str__(self):
        return self.__repr__()

    @property
    def loaded_kexts(self) -> [KextInfo]:
        return self.__loaded_kexts
