from abc import ABC

from la_panic.panic_parser.addresses.address_formater import reformat_register_value_to_fit

try:
    from functools import cached_property
except ImportError:
    from cached_property import cached_property


class AbstractCoreState(ABC):
    __crashed: bool = False

    pc: hex
    lr: hex
    fp: hex

    @property
    def crashed(self) -> bool:
        return self.__crashed

    @cached_property
    def registers(self) -> {str: hex}:
        registers: {str: hex} = {}

        for register_name, register_value in vars(self).items():
            if "crashed" in register_name:
                continue
            registers[register_name] = register_value

        return registers

    def __repr__(self):
        description = ""
        counter = 0

        for register_name, register_value in self.registers.items():
            if counter % 4 == 0:
                description += "\n"
            counter += 1

            try:
                value = f"0x{int(register_value, 16):016x}"
            except ValueError:
                value = reformat_register_value_to_fit(register_value)
            description += f'{register_name} = {value} '.rjust(30)

        return description

    def __str__(self):
        return self.__repr__()
