from typing import List

from la_panic.panic_parser.exception import LaPanicException


class EmptyRawCrashStack(LaPanicException):
    pass


class ValueNotExistInStack(LaPanicException):
    pass


class ReachedEndOfStack(LaPanicException):
    def __init__(self, already_read_stack: List[str]):
        super().__init__()

        self.read_stack = already_read_stack


class RawCrashStack(object):
    __index = 0
    __crash_stack: [str]

    def __init__(self, panic_info_string: str):
        self.__crash_stack = list(filter(None, panic_info_string.strip().split("\n")))

    def top(self):
        if len(self.__crash_stack) < self.__index:
            raise ReachedEndOfStack

        return self.__crash_stack[self.__index]

    def pop(self, number_of_pops: int = 1) -> [str]:
        if len(self.__crash_stack) == self.__index:
            raise EmptyRawCrashStack

        values = []
        for _ in range(number_of_pops):
            current_index_value = self.__crash_stack[self.__index]
            self.__index += 1
            values.append(current_index_value)

        return values

    def pop_one(self) -> str:
        return self.pop()[0]

    def pop_value_from_key_value_pair(self) -> str:
        return self.pop_one().split(':')[1].strip()

    def pop_hex_value_from_key_value_pair(self) -> hex:
        return hex(int(self.pop_one().split(':')[1], 16))

    def search_first_appearance(self, string_to_search: str) -> int:
        if len(self.__crash_stack) == self.__index:
            raise EmptyRawCrashStack

        for line_number, line in enumerate(self.__crash_stack[self.__index:]):
            if string_to_search in line:
                return line_number + self.__index

        raise ValueNotExistInStack

    def value_in_index(self, value_index: int) -> str:
        if len(self.__crash_stack) < value_index:
            raise ValueNotExistInStack

        return self.__crash_stack[value_index]

    def pop_until_line_containing(self, substring: str) -> [str]:
        if len(self.__crash_stack) == self.__index:
            raise EmptyRawCrashStack

        lines_until_substring: List[str] = []
        while substring not in self.__crash_stack[self.__index]:
            lines_until_substring.append(self.__crash_stack[self.__index])

            self.__index += 1
            if len(self.__crash_stack) == self.__index:
                raise ReachedEndOfStack(lines_until_substring)

        return lines_until_substring
