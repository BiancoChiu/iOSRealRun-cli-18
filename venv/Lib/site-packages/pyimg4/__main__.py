import plistlib
import sys
from typing import BinaryIO, Optional

import click

import pyimg4
from pyimg4 import Compression, Keybag

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(message=f'PyIMG4 {pyimg4.__version__}')
def cli():
    """A Python CLI tool for parsing Apple's Image4 format."""

    sys.tracebacklimit = 0


@cli.group()
def im4m() -> None:
    """Image4 manifest commands."""

    pass


@im4m.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input Image4 manifest file.',
    required=True,
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def im4m_info(input_: BinaryIO, verbose: bool) -> None:
    """Print available information on an Image4 manifest."""

    click.echo(f'Reading {input_.name}...')

    try:
        im4m = pyimg4.IM4M(input_.read())
    except:
        raise click.BadParameter(f'Failed to parse Image4 manifest file: {input_.name}')

    click.echo('Image4 manifest info:')

    if 0x8720 <= im4m.chip_id <= 0x8960:
        soc = f'S5L{im4m.chip_id:02x}'
    elif im4m.chip_id in range(0x7002, 0x8003):
        soc = f'S{im4m.chip_id:02x}'
    else:
        soc = f'T{im4m.chip_id:02x}'

    if verbose:
        click.echo(f'  Device Processor: {soc} ({hex(im4m.chip_id)})')
    else:
        click.echo(f'  Device Processor: {soc}')

    if im4m.ecid is not None:
        click.echo(f'  ECID (hex): {hex(im4m.ecid)}')

    if im4m.apnonce is not None:
        click.echo(f'  ApNonce (hex): {im4m.apnonce.hex()}')

    if im4m.sepnonce is not None:
        click.echo(f'  SepNonce (hex): {im4m.sepnonce.hex()}')

    if verbose:
        for p, prop in enumerate(im4m.properties):
            # Skip these, as we just printed them
            if prop.fourcc in ('BNCH', 'CHIP', 'ECID', 'snon'):
                continue

            if isinstance(prop.value, bytes):
                click.echo(f'  {prop.fourcc} (hex): {prop.value.hex()}')
            else:
                click.echo(f'  {prop.fourcc}: {prop.value}')

            if p == (len(im4m.properties) - 1):
                click.echo()

        click.echo(f'  Manifest images ({len(im4m.images)}):')
        for i, image in enumerate(im4m.images):
            click.echo(f'    {image.fourcc}:')

            for prop in image.properties:
                click.echo(
                    f'      {prop.fourcc}: {prop.value.hex() if isinstance(prop.value, bytes) else prop.value}'
                )

            if i != (len(im4m.images) - 1):
                click.echo()

    else:
        click.echo(
            f'  Manifest images ({len(im4m.images)}): {", ".join(i.fourcc for i in im4m.images)}'
        )


@im4m.command('verify')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input Image4 manifest file.',
    required=True,
)
@click.option(
    '-b',
    '--build-manifest',
    'build_manifest',
    type=click.File('rb'),
    help='Input build manifest file.',
    required=True,
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def im4m_verify(input_: BinaryIO, build_manifest: BinaryIO, verbose: bool) -> None:
    """Verify an Image4 manifest with a provided build manifest."""

    click.echo(f'Reading {input_.name}...')

    try:
        im4m = pyimg4.IM4M(input_.read())
    except:
        raise click.BadParameter(f'Failed to parse Image4 manifest file: {input_.name}')

    click.echo(f'Reading {build_manifest.name}...')

    try:
        manifest = plistlib.load(build_manifest)
    except plistlib.InvalidFileException:
        raise click.BadParameter(
            f'Failed to parse build manifest file: {build_manifest.name}'
        )

    for identity in manifest['BuildIdentities']:
        if not (
            int(identity['ApBoardID'], 16) == im4m.board_id
            and int(identity['ApChipID'], 16) == im4m.chip_id
        ):
            if verbose:
                click.echo(
                    f'Skipping build identity {manifest["BuildIdentities"].index(identity) + 1}...'
                )

            continue

        click.echo(
            f'Selected build identity: {manifest["BuildIdentities"].index(identity) + 1}'
        )
        for name, image_info in identity['Manifest'].items():
            if 'Digest' not in image_info.keys():
                if verbose:
                    click.echo(f'Component: {name} has no hash, skipping...')

                continue

            if verbose:
                click.echo(f'Verifying hash of component: {name}...')

            if not any(i for i in im4m.images if i.digest == image_info['Digest']):
                if verbose:
                    click.echo(
                        f'No hash found for component: {name} in Image4 manifest!'
                    )

                break
        else:
            click.echo(
                '\nImage4 manifest was successfully validated with the build manifest for the following restore:'
            )
            click.echo(f'Board config: {identity["Info"]["DeviceClass"]}')
            click.echo(f'Build ID: {identity["Info"]["BuildNumber"]}')
            click.echo(f'Restore type: {identity["Info"]["RestoreBehavior"]}')
            return

    click.echo('Image4 manifest is not valid for the provided build manifest!')


@im4m.command('extract')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input SHSH blob file.',
    required=True,
)
@click.option(
    '-o',
    '--output',
    'output',
    type=click.File('wb'),
    help='Output file.',
    required=True,
)
@click.option(
    '-u',
    '--update',
    'install_type',
    flag_value='updateInstall',
    help='Extract update Image4 manifest (if available).',
)
@click.option(
    '-n',
    '--no-nonce',
    'install_type',
    flag_value='noNonce',
    help='Extract no-nonce Image4 manifest (if available).',
)
def im4m_extract(
    input_: BinaryIO, output: BinaryIO, install_type: Optional[str]
) -> None:
    """Extract an Image4 manifest from an SHSH blob."""

    try:
        data = plistlib.load(input_)
    except plistlib.InvalidFileException:
        raise click.BadParameter(f'Failed to read SHSH blob: {input_.name}')

    if install_type == 'updateInstall':
        if 'updateInstall' not in data.keys():
            raise click.BadParameter(
                f'SHSH blob does not contain an update Image4 manifest: {input_.name}'
            )

        data = data['updateInstall']
    elif install_type == 'noNonce':
        if 'noNonce' not in data.keys():
            raise click.BadParameter(
                f'SHSH blob does not contain a no-nonce Image4 manifest: {input_.name}'
            )

        data = data['noNonce']

    if 'ApImg4Ticket' not in data.keys():
        raise click.BadParameter(
            f'SHSH blob does not contain an Image4 manifest: {input_.name}'
        )

    try:
        im4m = pyimg4.IM4M(data['ApImg4Ticket'])
    except:
        raise click.BadParameter(
            f'Failed to parse Image4 manifest in SHSH blob: {input_.name}'
        )

    output.write(im4m.output())
    click.echo(f'Image4 manifest outputted to: {output.name}')


@cli.group()
def im4p() -> None:
    """Image4 payload commands."""

    pass


@im4p.command('create')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input file.',
)
@click.option(
    '-o',
    '--output',
    type=click.File('wb'),
    required=True,
    help='Output file.',
)
@click.option('-f', '--fourcc', type=str, required=True, help='FourCC to set.')
@click.option(
    '-d',
    '--description',
    type=str,
    help='Description to set.',
)
@click.option(
    '--lzss', 'compression_type', flag_value='LZSS', help='LZSS compress the data.'
)
@click.option(
    '--lzfse',
    'compression_type',
    flag_value='LZFSE',
    help='LZFSE compress the data.',
)
@click.option(
    '--extra',
    type=click.File('rb'),
    help='Extra IM4P payload data to set (requires --lzss).',
)
def im4p_create(
    input_: BinaryIO,
    output: BinaryIO,
    fourcc: str,
    description: Optional[str],
    compression_type: Optional[str],
    extra: Optional[BinaryIO],
) -> None:
    """Create an Image4 payload file."""

    if len(fourcc) != 4:
        raise click.BadParameter('FourCC must be 4 characters long')

    click.echo(f'Reading {input_.name}...')

    try:
        im4p = pyimg4.IM4P(
            fourcc=fourcc, description=description, payload=input_.read()
        )
    except:
        raise click.BadParameter(f'Failed to parse Image4 payload file: {input_.name}')

    if extra is not None:
        if compression_type != 'LZSS':
            raise click.BadParameter('--extra requires --lzss flag to be set')

        click.echo(f'Reading extra: {extra.name}...')
        im4p.payload.extra = extra.read()

    if compression_type is not None:
        compression_type = getattr(Compression, compression_type)

        if im4p.payload.compression != Compression.NONE:
            raise click.BadParameter(
                f'Payload is already {im4p.payload.compression.name} compressed'
            )

        click.echo(f'Compressing payload using {compression_type.name}...')
        im4p.payload.compress(compression_type)

    output.write(im4p.output())
    click.echo(f'Image4 payload outputted to: {output.name}')


@im4p.command('extract')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input Image4 payload file.',
)
@click.option(
    '-o',
    '--output',
    type=click.File('wb'),
    required=True,
    help='File to output Image4 payload data to.',
)
@click.option(
    '--extra',
    type=click.File('wb'),
    help='File to output extra Image4 payload data to.',
)
@click.option(
    '--no-decompress',
    'decompress',
    default=True,
    is_flag=True,
    help="Don't decompress the Image4 payload data.",
)
@click.option('--iv', help='The IV used to encrypt the Image4 payload data.')
@click.option('--key', help='The key used to encrypt the Image4 payload data.')
def im4p_extract(
    input_: BinaryIO,
    output: BinaryIO,
    extra: Optional[BinaryIO],
    decompress: bool,
    iv: Optional[str],
    key: Optional[str],
) -> None:
    """Extract data from an Image4 payload."""

    click.echo(f'Reading {input_.name}...')

    try:
        im4p = pyimg4.IM4P(input_.read())
    except:
        raise click.BadParameter(f'Failed to parse Image4 payload file: {input_.name}')

    if iv is None and key is None:
        if im4p.payload.encrypted is True:
            click.echo('[NOTE] Image4 payload data is encrypted')

    elif iv is None or key is None:
        if im4p.payload.encrypted is True:
            raise click.BadParameter('You must specify both the IV and the key')

    elif im4p.payload.encrypted is True:
        click.echo('[NOTE] Image4 payload data is encrypted, decrypting...')

        if iv.lower().startswith('0x'):
            iv = iv[2:]

        if key.lower().startswith('0x'):
            key = key[2:]

        try:
            iv = bytes.fromhex(iv)
        except TypeError:
            raise click.BadParameter('Decryption IV must be a hex string')

        try:
            key = bytes.fromhex(key)
        except TypeError:
            raise click.BadParameter('Decryption key must be a hex string')

        if len(iv) != 16:
            raise click.BadParameter('Decryption IV must be 16 bytes long')

        if len(key) == 32:
            im4p.payload.decrypt(Keybag(key=key, iv=iv))

        else:
            raise click.BadParameter('Decryption key must be 32 bytes long')

    if im4p.payload.compression != Compression.NONE:
        if decompress:
            click.echo(
                f'[NOTE] Image4 payload data is {im4p.payload.compression.name} compressed, decompressing...'
            )

            im4p.payload.decompress()
        else:
            click.echo(
                f'[NOTE] Image4 payload data is {im4p.payload.compression.name} compressed, skipping decompression'
            )

    if extra is not None:
        if im4p.payload.extra is None:
            click.echo('[WARN] No extra Image4 payload data found')
        else:
            click.echo(f'Extracted extra Image4 payload data: to {extra.name}.')
            extra.write(im4p.payload.extra)

    output.write(im4p.payload.output().data)

    click.echo(f'Extracted Image4 payload data to: {output.name}')


@im4p.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input Image4 payload file.',
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def im4p_info(input_: BinaryIO, verbose: bool) -> None:
    """Print available information on an Image4 payload."""

    click.echo(f'Reading {input_.name}...')

    try:
        im4p = pyimg4.IM4P(input_.read())
    except:
        raise click.BadParameter(f'Failed to parse Image4 payload file: {input_.name}')

    click.echo('Image4 payload info:')
    click.echo(f'  FourCC: {im4p.fourcc}')
    click.echo(f'  Description: {im4p.description}')

    if verbose:
        payload_size = len(im4p.payload)
    else:
        payload_size = f'{round(len(im4p.payload) / 1000, 2)}KB'
    click.echo(f'  Data size: {payload_size}')

    if im4p.payload.compression != pyimg4.Compression.NONE:
        compression_type = (
            'LZFSE'
            if im4p.payload.compression
            in (pyimg4.Compression.LZFSE, pyimg4.Compression.LZFSE_ENCRYPTED)
            else im4p.payload.compression.name
        )
        click.echo(f'  Data compression type: {compression_type}')

        if verbose:
            payload_size = im4p.payload.size
        else:
            payload_size = f'{round(im4p.payload.size / 1000, 2)}KB'
        click.echo(f'  Data size (uncompressed): {payload_size}')

    if im4p.payload.extra is not None:
        if verbose:
            extra_size = len(im4p.payload.extra)
        else:
            extra_size = f'{round(len(im4p.payload.extra) / 1000, 2)}KB'

        click.echo(f'  Extra data size: {extra_size}')

    click.echo(f'  Encrypted: {im4p.payload.encrypted}')
    if im4p.payload.encrypted:
        click.echo(f'  Keybags ({len(im4p.payload.keybags)}):')
        for k, kb in enumerate(im4p.payload.keybags):
            click.echo(f'    Type: {kb.type.name}')
            click.echo(f'    IV: {kb.iv.hex()}')
            click.echo(f'    Key: {kb.key.hex()}')

            if k != (len(im4p.payload.keybags) - 1):
                click.echo()

    if len(im4p.properties) > 0:
        if verbose:
            click.echo('\n  Properties:')
            for p, prop in enumerate(im4p.properties):
                if isinstance(prop.value, bytes):
                    click.echo(f'    {prop.fourcc} (hex): {prop.value.hex()}')
                else:
                    click.echo(f'    {prop.fourcc}: {prop.value}')

                if p != (len(im4p.properties) - 1):
                    click.echo()
        else:
            click.echo(
                f'\n  Properties ({len(im4p.properties)}): {", ".join(i.fourcc for i in im4p.properties)}'
            )


@cli.group()
def im4r() -> None:
    """Image4 restore info commands."""

    pass


@im4r.command('create')
@click.option(
    '-g',
    '--boot-nonce',
    type=str,
    required=True,
    help='The boot nonce used to encrypt the Image4 restore info.',
)
@click.option(
    '-o',
    '--output',
    type=click.File('wb'),
    required=True,
    help='File to output Image4 restore info to.',
)
def im4r_create(boot_nonce: str, output: BinaryIO) -> None:
    """Create an Image4 restore info file."""

    click.echo(f'Creating Image4 restore info file with boot nonce: {boot_nonce}...')

    if boot_nonce.lower().startswith('0x'):
        boot_nonce = boot_nonce[2:]

    try:
        boot_nonce = bytes.fromhex(boot_nonce)
    except TypeError:
        raise click.BadParameter('Boot nonce must be a hex string')

    if len(boot_nonce) != 8:
        raise click.BadParameter('Boot nonce must be 8 bytes long')

    im4r = pyimg4.IM4R(boot_nonce=boot_nonce)

    output.write(im4r.output())
    click.echo(f'Image4 restore info outputted to: {output.name}')


@im4r.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input Image4 restore info file.',
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def im4r_info(input_: BinaryIO, verbose: bool) -> None:
    """Print available information on an Image4 restore info file."""

    click.echo(f'Reading {input_.name}...')

    try:
        im4r = pyimg4.IM4R(input_.read())
    except:
        raise click.BadParameter(
            f'Failed to parse Image4 restore info file: {input_.name}'
        )

    click.echo('Image4 restore info:')
    if im4r.boot_nonce is not None:
        click.echo(f'  Boot nonce (hex): 0x{im4r.boot_nonce.hex()}')

    extra_props = [prop for prop in im4r.properties if prop.fourcc != 'BNCN']
    if extra_props:
        if verbose:
            click.echo(f'  Properties ({len(extra_props)}):')
            for p, prop in enumerate(extra_props):
                if isinstance(prop.value, bytes):
                    click.echo(f'    {prop.fourcc} (hex): {prop.value.hex()}')
                else:
                    click.echo(f'    {prop.fourcc}: {prop.value}')

                if p != (len(extra_props) - 1):
                    click.echo()
        else:
            click.echo(f'  Properties ({len(extra_props)}): {", ".join(extra_props)}')


@cli.group()
def img4() -> None:
    """Image4 commands."""

    pass


@img4.command('create')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input file.',
)
@click.option('-f', '--fourcc', type=str, help='FourCC to set.')
@click.option(
    '-d',
    '--description',
    type=str,
    help='Description to set.',
)
@click.option(
    '--lzss', 'compression_type', flag_value='LZSS', help='LZSS compress the data.'
)
@click.option(
    '--lzfse',
    'compression_type',
    flag_value='LZFSE',
    help='LZFSE compress the data.',
)
@click.option(
    '--extra',
    type=click.File('rb'),
    help='Extra IM4P payload data to set (requires --lzss).',
)
@click.option(
    '-p',
    '--im4p',
    type=click.File('rb'),
    help='Input Image4 payload file.',
)
@click.option(
    '-m',
    '--im4m',
    type=click.File('rb'),
    required=True,
    help='Input Image4 manifest file.',
)
@click.option(
    '-r',
    '--im4r',
    type=click.File('rb'),
    help='Input Image4 restore info file.',
)
@click.option(
    '-g',
    '--boot-nonce',
    'boot_nonce',
    type=str,
    help='Boot nonce to set in Image4 restore info.',
)
@click.option(
    '-o', '--output', type=click.File('wb'), required=True, help='Output file.'
)
def img4_create(
    input_: Optional[BinaryIO],
    fourcc: Optional[str],
    description: Optional[str],
    compression_type: Optional[str],
    extra: Optional[BinaryIO],
    im4p: Optional[BinaryIO],
    im4m: BinaryIO,
    im4r: Optional[BinaryIO],
    boot_nonce: Optional[str],
    output: BinaryIO,
):
    """Create an Image4 file."""

    if all(i is None for i in (input_, im4p, im4m, im4r, boot_nonce)):
        raise click.BadParameter('You must specify at least one input file')

    img4 = pyimg4.IMG4()
    if im4p is not None:
        click.echo(f'Reading {im4p.name}...')

        try:
            im4p = pyimg4.IM4P(im4p.read())
        except:
            raise click.BadParameter(
                f'Failed to parse Image4 payload file: {im4p.name}'
            )

        img4.im4p = im4p

    elif input_ is not None:
        if fourcc is None:
            raise click.BadParameter('No FourCC specified')

        click.echo(f'Reading {input_.name}...')
        im4p = pyimg4.IM4P(
            fourcc=fourcc, description=description, payload=input_.read()
        )

        if extra is not None:
            click.echo(f'Reading extra Image4 payload data: {extra.name}...')
            im4p.payload.extra = extra.read()

        if compression_type is not None:
            compression_type = getattr(Compression, compression_type)
            click.echo(f'Compressing payload using {compression_type.name}...')
            im4p.payload.compress(compression_type)

        img4.im4p = im4p

    if im4m is not None:
        click.echo(f'Reading {im4m.name}...')

        try:
            im4m = pyimg4.IM4M(im4m.read())
        except:
            raise click.BadParameter(
                f'Failed to parse Image4 manifest file: {im4m.name}'
            )

        img4.im4m = im4m

    if im4r is not None:
        click.echo(f'Reading {im4r.name}...')

        try:
            im4r = pyimg4.IM4R(im4r.read())
        except:
            raise click.BadParameter(
                f'Failed to parse Image4 restore info file: {im4r.name}'
            )

        img4.im4r = im4r

    elif boot_nonce is not None:
        click.echo(f'Creating Image4 restore info with boot nonce: {boot_nonce}...')

        if boot_nonce.lower().startswith('0x'):
            boot_nonce = boot_nonce[2:]

        try:
            boot_nonce = bytes.fromhex(boot_nonce)
        except TypeError:
            raise click.BadParameter('Boot nonce must be a hex string')

        if len(boot_nonce) != 8:
            raise click.BadParameter('Boot nonce must be 8 bytes long')

        img4.im4r = pyimg4.IM4R(boot_nonce=boot_nonce)

    click.echo('Outputting Image4...')
    output.write(img4.output())
    click.echo(f'Image4 file outputted to: {output.name}')


@img4.command('extract')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input Image4 file.',
    required=True,
)
@click.option(
    '-r',
    '--raw',
    'raw',
    type=click.File('wb'),
    help='File to output Image4 payload data to.',
)
@click.option(
    '--extra',
    type=click.File('wb'),
    help='File to output extra Image4 payload data to.',
)
@click.option(
    '-p',
    '--im4p',
    type=click.File('wb'),
    help='File to output Image4 payload to.',
)
@click.option(
    '-m',
    '--im4m',
    type=click.File('wb'),
    help='File to output Image4 manifest to.',
)
@click.option(
    '-r',
    '--im4r',
    type=click.File('wb'),
    help='File to output Image4 restore info to.',
)
def img4_extract(
    input_: BinaryIO,
    raw: Optional[BinaryIO],
    extra: Optional[BinaryIO],
    im4p: Optional[BinaryIO],
    im4m: Optional[BinaryIO],
    im4r: Optional[BinaryIO],
) -> None:
    """Extract Image4 manifest/payload/restore info from an Image4 file."""

    click.echo(f'Reading {input_.name}...')

    try:
        img4 = pyimg4.IMG4(input_.read())
    except:
        raise click.BadParameter(f'Failed to parse Image4 file: {input_.name}')

    if all(i is None for i in (raw, extra, im4p, im4m, im4r)):
        raise click.BadParameter('You must specify at least one output file')

    if raw is not None:
        raw.write(img4.im4p.payload.data)
        click.echo(f'Extracted Image4 payload data to: {raw.name}')

    if extra is not None:
        if img4.im4p.payload.extra is None:
            raise click.BadParameter('No extra Image4 payload data found')

        extra.write(img4.im4p.payload.extra)
        click.echo(f'Extracted extra Image4 payload data to: {extra.name}')

    if im4p is not None:
        if img4.im4p is None:
            raise click.BadParameter('Image4 payload not found in Image4 file')

        im4p.write(img4.im4p.output())
        click.echo(f'Extracted Image4 payload to: {im4p.name}')

    if im4m is not None:
        if img4.im4m is None:
            raise click.BadParameter('Image4 manifest not found in Image4 file')

        im4m.write(img4.im4m.output())
        click.echo(f'Extracted Image4 manifest to: {im4m.name}')

    if im4r is not None:
        if img4.im4r is None:
            raise click.BadParameter('Image4 restore info not found in Image4 file')

        im4r.write(img4.im4r.output())
        click.echo(f'Extracted Image4 restore info to: {im4r.name}')


@img4.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input Image4 file.',
    required=True,
)
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
def img4_info(input_: BinaryIO, verbose: bool) -> None:
    """Print available information on an Image4 file."""

    click.echo(f'Reading {input_.name}...')

    try:
        img4 = pyimg4.IMG4(input_.read())
    except:
        raise click.BadParameter(f'Failed to parse Image4 file: {input_.name}')

    click.echo('Image4 info:')

    click.echo('  Image4 payload info:')
    click.echo(f'    FourCC: {img4.im4p.fourcc}')
    click.echo(f'    Description: {img4.im4p.description}')
    click.echo(f'    Data size: {round(len(img4.im4p.payload) / 1000, 2)}KB')

    if (
        img4.im4p.payload.encrypted is False
        and img4.im4p.payload.compression != pyimg4.Compression.NONE
    ):
        click.echo(f'    Data compression type: {img4.im4p.payload.compression.name}')

        img4.im4p.payload.decompress()
        click.echo(
            f'    Data size (uncompressed): {round(len(img4.im4p.payload) / 1000, 2)}KB'
        )

    if img4.im4p.payload.extra is not None:
        if verbose:
            extra_size = len(img4.im4p.payload.extra)
        else:
            extra_size = f'{round(len(img4.im4p.payload.extra) / 1000, 2)}KB'

        click.echo(f'    Extra data size: {extra_size}')

    click.echo(f'    Encrypted: {img4.im4p.payload.encrypted}')
    if img4.im4p.payload.encrypted:
        click.echo(f'    Keybags ({len(img4.im4p.payload.keybags)}):')
        for k, kb in enumerate(img4.im4p.payload.keybags):
            click.echo(f'      Type: {kb.type.name}')
            click.echo(f'      IV: {kb.iv.hex()}')
            click.echo(f'      Key: {kb.key.hex()}')

            if k != (len(img4.im4p.payload.keybags) - 1):
                click.echo()

    click.echo('\n  Image4 manifest info:')

    if 0x8720 <= img4.im4m.chip_id <= 0x8960:
        soc = f'S5L{img4.im4m.chip_id:02x}'
    elif img4.im4m.chip_id in range(0x7002, 0x8003):
        soc = f'S{img4.im4m.chip_id:02x}'
    else:
        soc = f'T{img4.im4m.chip_id:02x}'

    if verbose:
        click.echo(f'    Device Processor: {soc} ({hex(img4.im4m.chip_id)})')
    else:
        click.echo(f'    Device Processor: {soc}')

    if img4.im4m.ecid is not None:
        click.echo(f'    ECID (hex): {hex(img4.im4m.ecid)}')

    if img4.im4m.apnonce is not None:
        click.echo(f'    ApNonce (hex): {img4.im4m.apnonce.hex()}')

    if img4.im4m.sepnonce is not None:
        click.echo(f'    SepNonce (hex): {img4.im4m.sepnonce.hex()}')

    if verbose:
        for p, prop in enumerate(img4.im4m.properties):
            # Skip these, as we just printed them
            if prop.fourcc in ('BNCH', 'CHIP', 'ECID', 'snon'):
                continue

            if isinstance(prop.value, bytes):
                click.echo(f'    {prop.fourcc} (hex): {prop.value.hex()}')
            else:
                click.echo(f'    {prop.fourcc}: {prop.value}')

            if p == (len(img4.im4m.properties) - 1):
                click.echo()

        click.echo(f'    Manifest images ({len(img4.im4m.images)}):')
        for i, image in enumerate(img4.im4m.images):
            click.echo(f'      {image.fourcc}:')

            for prop in image.properties:
                click.echo(
                    f'        {prop.fourcc}: {prop.value.hex() if isinstance(prop.value, bytes) else prop.value}'
                )

            if i != (len(img4.im4m.images) - 1):
                click.echo()

    else:
        click.echo(
            f'    Manifest images ({len(img4.im4m.images)}): {", ".join(i.fourcc for i in img4.im4m.images)}'
        )

    if img4.im4r is not None:
        click.echo('\n  Image4 restore info:')

        if img4.im4r.boot_nonce is not None:
            click.echo(f'    Boot nonce (hex): 0x{img4.im4r.boot_nonce.hex()}')

        extra_props = [prop for prop in img4.im4r.properties if prop.fourcc != 'BNCN']
        if extra_props:
            if verbose:
                click.echo(f'    Properties ({len(extra_props)}):')
                for p, prop in enumerate(extra_props):
                    if isinstance(prop.value, bytes):
                        click.echo(f'      {prop.fourcc} (hex): {prop.value.hex()}')
                    else:
                        click.echo(f'      {prop.fourcc}: {prop.value}')

                    if p != (len(extra_props) - 1):
                        click.echo()
            else:
                click.echo(
                    f'    Properties ({len(extra_props)}): {", ".join(extra_props)}'
                )


if __name__ == '__main__':
    cli()
