import click

from pygnuutils.cli.basename import cli as basename_cli
from pygnuutils.cli.basenc import cli as basenc_cli
from pygnuutils.cli.ls import cli as ls_cli
from pygnuutils.cli.yes import cli as yes_cli


def main():
    cli_commands = click.CommandCollection(sources=[
        basename_cli,
        basenc_cli,
        ls_cli,
        yes_cli,
    ])
    cli_commands()


if __name__ == '__main__':
    main()
