from la_panic.data_structure.raw_crash_stack import RawCrashStack


class ZoneInfoHexRange(object):
    __start: hex
    __end: hex

    def __init__(self, zone_info_range: str):
        range_parts = zone_info_range.strip().split("-")
        self.__start = hex(int(range_parts[0], 16))
        self.__end = hex(int(range_parts[1], 16))

    @property
    def start(self):
        return self.__start

    @property
    def end(self):
        return self.__end


class ZoneInfo(object):
    def __init__(self, panic_infos: RawCrashStack):
        # Remove Zone info header
        panic_infos.pop_one()

        self.__zone_map = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        self.__vm = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        self.__ro = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        self.__gens = [
            ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair()),
            ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair()),
            ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair()),
            ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        ]

        self.__data = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        self.__metadata = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        self.__bitmaps = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())

        if 'extra' in panic_infos.top().lower():
            self.__extra = ZoneInfoHexRange(panic_infos.pop_value_from_key_value_pair())
        else:
            self.__extra = None
