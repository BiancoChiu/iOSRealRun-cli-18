import json
from pathlib import Path

import click

from la_panic.panic_parser.addresses.address_symbol_mapper import AddressSymbolMapper
from la_panic.panic_parser.kernel_panic import KernelPanic


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def parser():
    pass


def parse_panic(panic_file, address_symbols_file_path) -> KernelPanic:
    AddressSymbolMapper.parse(Path(address_symbols_file_path))
    metadata = json.loads(panic_file.readline())
    return KernelPanic(metadata, panic_file.read(), panic_file.name)


@parser.command('parse', cls=click.Command)
@click.argument('panic_file', type=click.File("rt"), required=True)
@click.argument('address_symbols_file_path', type=click.Path(),
                default=f"{Path(__file__).parent}/addresses/symbols.txt")
def parse(panic_file, address_symbols_file_path):
    panic = parse_panic(panic_file, address_symbols_file_path)
    print(f"{panic}\n")
