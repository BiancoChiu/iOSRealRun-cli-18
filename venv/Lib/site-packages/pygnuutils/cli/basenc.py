import click

from pygnuutils.basenc import Basenc


@click.group()
def cli():
    pass


@cli.command()
@click.argument('file', required=False, default='-')
@click.option('--base64', is_flag=True)
@click.option('--base64url', is_flag=True)
@click.option('--base32', is_flag=True)
@click.option('--base32hex', is_flag=True)
@click.option('--base16', is_flag=True)
@click.option('--base2msbf', is_flag=True)
@click.option('--base2lsbf', is_flag=True)
@click.option('-d', '--decode', is_flag=True)
@click.option('-i', '--ignore-garbage', is_flag=True)
@click.option('-w', '--wrap', type=click.INT, default=76)
@click.option('--z85', is_flag=True)
def basenc(file, base64, base64url, base32, base32hex, base16, base2msbf, base2lsbf, decode, ignore_garbage, wrap, z85):
    Basenc()(
        file=file,
        base64=base64,
        base64url=base64url,
        base32=base32,
        base32hex=base32hex,
        base16=base16,
        base2msbf=base2msbf,
        base2lsbf=base2lsbf,
        decode=decode,
        ignore_garbage=ignore_garbage,
        wrap=wrap,
        z85=z85,
    )
