from typing import Mapping, Any


class PagesInfo(object):
    __size: int
    __wanted: int
    __reclaimed: int
    __active: int
    __throttled: int
    __file_backed: int
    __wired: int
    __purgeable: int
    __inactive: int
    __free: int
    __speculative: int

    def __init__(self, json_data: Mapping[str, Any]):
        self.__size = int(json_data['pageSize'])
        self.__wanted = int(json_data['memoryPressureDetails']['pagesWanted'])
        self.__reclaimed = int(json_data['memoryPressureDetails']['pagesReclaimed'])
        self.__active = int(json_data['memoryPages']['active'])
        self.__throttled = int(json_data['memoryPages']['throttled'])
        self.__file_backed = int(json_data['memoryPages']['fileBacked'])
        self.__wired = int(json_data['memoryPages']['wired'])
        self.__purgeable = int(json_data['memoryPages']['purgeable'])
        self.__inactive = int(json_data['memoryPages']['inactive'])
        self.__free = int(json_data['memoryPages']['free'])
        self.__speculative = int(json_data['memoryPages']['speculative'])


class MemoryStatus(object):
    __compressor_size: int
    __compressions: int
    __decompressions: int
    __busy_buffer_count: int
    __memory_pressure: bool
    __pages_info: PagesInfo

    def __init__(self, json_data: Mapping[str, Any]):
        self.__compressor_size = int(json_data['compressorSize'])
        self.__compressions = int(json_data['compressions'])
        self.__decompressions = int(json_data['decompressions'])
        self.__busy_buffer_count = int(json_data['busyBufferCount'])
        self.__memory_pressure = False if json_data['memoryPressure'] == 'false' else True
        self.__pages_info = PagesInfo(json_data)
