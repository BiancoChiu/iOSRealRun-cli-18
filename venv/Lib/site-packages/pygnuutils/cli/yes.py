import click

from pygnuutils.yes import Yes


@click.group()
def cli():
    pass


@cli.command()
@click.argument('string_', nargs=-1)
def yes(string_):
    Yes()(*string_)
