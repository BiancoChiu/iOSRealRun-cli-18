import json

import click

from pykdebugparser.kd_buf_parser import KdBufParser
from pykdebugparser.pykdebugparser import PyKdebugParser


@click.group()
def cli():
    pass


def print_with_count(generator, count: int):
    i = 0
    for obj in generator:
        if i == count:
            break
        print(obj)
        i += 1


class BasedIntParamType(click.ParamType):
    name = 'based int'

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail(f'{value!r} is not a valid int.', param, ctx)


BASED_INT = BasedIntParamType()

dump_input = click.argument('kdebug_dump', type=click.File('rb'))
count = click.option('-c', '--count', type=click.INT, default=-1,
                     help='Number of events to print. Omit to endless sniff.')
tid_filter = click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
show_tid = click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
process_filter = click.option('--process', default=None, help='Process ID / name to filter. Omit for all.')
class_filter = click.option('-cf', '--class-filters', multiple=True, type=BASED_INT,
                            help='Events class filter. Omit for all.')
subclass_filter = click.option('-sf', '--subclass-filters', multiple=True, type=BASED_INT,
                               help='Events subclass filter. Omit for all.')


@cli.command()
@dump_input
@count
@tid_filter
@show_tid
@class_filter
@subclass_filter
def kevents(kdebug_dump, count, tid, show_tid, class_filters, subclass_filters):
    parser = PyKdebugParser()
    parser.filter_class = class_filters
    parser.filter_subclass = subclass_filters
    parser.filter_tid = tid
    parser.show_tid = show_tid
    print_with_count(parser.formatted_kevents(kdebug_dump), count)


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
@class_filter
@subclass_filter
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
def traces(kdebug_dump, count, tid, process, show_tid, class_filters, subclass_filters, color):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.filter_class = list(class_filters)
    parser.filter_subclass = list(subclass_filters)
    parser.show_tid = show_tid
    parser.color = color
    print_with_count(parser.formatted_traces(kdebug_dump), count)


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
def callstacks(kdebug_dump, count, tid, process, show_tid):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.show_tid = show_tid
    print_with_count(parser.formatted_callstacks(kdebug_dump), count)


@cli.command()
@dump_input
def processes(kdebug_dump):
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.processes, indent=4))


@cli.command()
@dump_input
def kexts(kdebug_dump):
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.kernel_extensions, indent=4))


@cli.command()
@dump_input
def images(kdebug_dump):
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.images, indent=4))


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
def logs(kdebug_dump, count, tid, process, show_tid):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.show_tid = show_tid
    print_with_count(parser.formatted_logs(kdebug_dump), count)


if __name__ == '__main__':
    cli()
