from la_panic.panic_parser.addresses.la_address import LaAddress
from la_panic.panic_parser.core_state.abstract_core_state import AbstractCoreState


class CrashedCoreState(AbstractCoreState):
    __slid_register_names = ["pc", "lr"]

    def __init__(self, core_state_info: [str]):
        for line in core_state_info:
            register_line = line.split(':')
            register_name = register_line[0].strip()
            for part in register_line[1:]:
                address_value_and_next_register_name = list(filter(None, part.split(" ")))

                if register_name in self.__slid_register_names:
                    address = LaAddress(address_value_and_next_register_name[0]).unslide_named_address
                else:
                    address = hex(int(address_value_and_next_register_name[0], 16))

                self.__setattr__(register_name, address)

                if len(address_value_and_next_register_name) != 1:
                    register_name = address_value_and_next_register_name[1]
