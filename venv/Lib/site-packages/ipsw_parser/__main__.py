#!/usr/bin/env python3
import logging
from pathlib import Path
from typing import Optional
from zipfile import ZipFile

import click
import coloredlogs
from remotezip2 import RemoteZip

from ipsw_parser.ipsw import IPSW

coloredlogs.install(level=logging.DEBUG)

logging.getLogger('asyncio').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True
logging.getLogger('blib2to3.pgen2.driver').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True

logger = logging.getLogger(__name__)

PEM_DB_ENV_VAR = 'IPSW_PARSER_PEM_DB'


def handle_ipsw_argument(ctx: click.Context, param: click.Argument, value: str) -> IPSW:
    if value.startswith('http://') or value.startswith('https://'):
        return IPSW(RemoteZip(value))
    return IPSW(ZipFile(Path(value).expanduser()))


ipsw_argument = click.argument('ipsw', callback=handle_ipsw_argument)
pem_db_option = click.option('--pem-db', envvar=PEM_DB_ENV_VAR,
                             help='Path DB file url (can be either a filesystem path or an HTTP URL). '
                                  'Alternatively, use the IPSW_PARSER_PEM_DB envvar.')


@click.group()
def cli() -> None:
    """ CLI utility for extracting info from IPSW files """
    pass


@cli.command('info')
@ipsw_argument
def info(ipsw) -> None:
    """ Parse given .ipsw basic info """
    print(f'SupportedProductTypes: {ipsw.build_manifest.supported_product_types}')
    print(f'ProductVersion: {ipsw.build_manifest.product_version}')
    print(f'ProductBuildVersion: {ipsw.build_manifest.product_build_version}')

    development_files = ipsw.get_development_files()
    if development_files:
        print('DevelopmentFiles:')
        for file in development_files:
            print(f'- {file}')


@cli.command('extract')
@ipsw_argument
@click.argument('output', type=click.Path(exists=False))
@pem_db_option
def extract(ipsw: IPSW, output: str, pem_db: Optional[str]) -> None:
    """ Extract .ipsw into filesystem layout """
    output = Path(output)

    if not output.exists():
        output.mkdir(parents=True, exist_ok=True)

    ipsw.build_manifest.build_identities[0].extract(output, pem_db=pem_db)
    ipsw.archive.extractall(
        path=output, members=[f for f in ipsw.archive.filelist if f.filename.startswith('Firmware')])


@cli.command('extract-kernel')
@ipsw_argument
@click.argument('output', type=click.Path(exists=False))
@click.option('--arch', help='Arch name to extract using lipo')
def extract_kernel(ipsw: IPSW, output: str, arch: Optional[str]) -> None:
    """ Extract kernelcache from given .ipsw into given output filename """
    Path(output).write_bytes(ipsw.build_manifest.build_identities[0].get_kernelcache_payload(arch=arch))


@cli.command('device-support')
@ipsw_argument
@pem_db_option
def device_support(ipsw: IPSW, pem_db: Optional[str]) -> None:
    """ Create DeviceSupport directory """
    ipsw.create_device_support(pem_db=pem_db)


if __name__ == '__main__':
    cli()
