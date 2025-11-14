from pathlib import Path
from typing import Mapping


class AddressSymbolMapper(object):
    __map: Mapping[str, str] = {}

    @staticmethod
    def parse(address_symbols_file_path: Path):
        if not address_symbols_file_path.exists():
            return

        building_map = {}
        with address_symbols_file_path.open("r") as address_symbols_file:
            for line in address_symbols_file.readlines():
                address_and_name = line.split("=")
                building_map[address_and_name[1].split(";")[0].strip()] = address_and_name[0].strip()

        AddressSymbolMapper.__map = {key: building_map[key] for key in sorted(building_map)}

    @staticmethod
    def address_name(address: int) -> str:
        try:
            return AddressSymbolMapper.__map[hex(address)]
        except KeyError:
            return hex(address)
