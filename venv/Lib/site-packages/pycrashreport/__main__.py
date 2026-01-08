import click

from pycrashreport.crash_report import get_crash_report_from_file


@click.command()
@click.argument('file', type=click.File('rt'))
def cli(file):
    print(get_crash_report_from_file(file))


if __name__ == '__main__':
    cli()
