import click

from pygnuutils.basename import Basename


@click.group()
def cli():
    pass


@cli.command()
@click.argument('name', nargs=-1)
@click.option('-a', '--multiple', is_flag=True)
@click.option('-s', '--suffix', default='')
@click.option('-z', '--zero', is_flag=True)
def basename(name, multiple, suffix, zero):
    Basename()(*name, multiple=multiple, suffix=suffix, zero=zero)
