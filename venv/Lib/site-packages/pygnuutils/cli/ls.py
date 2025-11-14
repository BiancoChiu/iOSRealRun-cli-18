import click

from pygnuutils.ls import Ls, Formats, IndicatorStyle, SortType, TimeType, TimeStyle

FORMAT_NAMES = {
    'verbose': Formats.LONG_FORMAT,
    'long': Formats.LONG_FORMAT,
    'commas': Formats.WITH_COMMAS,
    'horizontal': Formats.HORIZONTAL,
    'across': Formats.HORIZONTAL,
    'vertical': Formats.MANY_PER_LINE,
    'single-column': Formats.ONE_PER_LINE,
}

TIME_STYLE_NAMES = {
    'full-iso': TimeStyle.FULL_ISO,
    'long-iso': TimeStyle.LONG_ISO,
    'iso': TimeStyle.ISO,
    'locale': TimeStyle.LOCALE,
}

INDICATOR_STYLE_NAMES = {
    'none': IndicatorStyle.NONE,
    'slash': IndicatorStyle.SLASH,
    'file_type': IndicatorStyle.FILE_TYPE,
    'classify': IndicatorStyle.CLASSIFY,
}

SORT_TYPE_NAMES = {
    'none': SortType.NONE,
    'time': SortType.TIME,
    'size': SortType.SIZE,
    'extension': SortType.EXTENSION,
    'version': SortType.VERSION,
    'width': SortType.WIDTH,
}

TIME_TYPE_NAMES = {
    'atime': TimeType.ATIME,
    'access': TimeType.ATIME,
    'use': TimeType.ATIME,
    'ctime': TimeType.CTIME,
    'status': TimeType.CTIME,
    'birth': TimeType.BTIME,
    'creation': TimeType.BTIME,
}


@click.group()
def cli():
    pass


@cli.command()
@click.option('-a', '--all', 'all_', is_flag=True, help='do not ignore entries starting with .')
@click.option('-A', '--almost-all', is_flag=True, help='do not list implied . and ..')
@click.option('--author', is_flag=True, help='with -l, print the author of each file')
# Add escape
@click.option('--block-size', help='''with -l, scale sizes by SIZE when printing them; e.g.,
              '--block-size=M'; see SIZE format below''')
@click.option('-B', '--ignore-backups', is_flag=True, help='do not list implied entries ending with ~')
@click.option('-c', 'ctime', is_flag=True, help='''with -lt: sort by, and show, ctime (time of last
              modification of file status information); with -l: show
              ctime and sort by name; otherwise: sort by ctime, newest
              first''')
@click.option('-C', 'columns_format', is_flag=True, help='list entries by columns')
@click.option('-d', 'directory', is_flag=True, help='list directories themselves, not their contents')
@click.option('-f', 'fast', is_flag=True, help='do not sort, enable -aU, disable -ls --color')
@click.option('-F', '--classify', is_flag=True, help='append indicator (one of */=>@|) to entries')
@click.option('--file-type', is_flag=True, help='likewise, except do not append \'*\'')
@click.option('--format', 'format_', type=click.Choice(list(FORMAT_NAMES.keys())),
              callback=lambda ctx, param, value: None if value is None else FORMAT_NAMES[value],
              help='likewise, except do not append \'*\'')
@click.option('--full-time', is_flag=True, help='like -l --time-style=full-iso')
@click.option('-g', 'group_only', is_flag=True, help='like -l, but do not list owner')
@click.option('--group-directories-first', is_flag=True, help='''group directories before files;

              can be augmented with a --sort option, but any use of
              --sort=none (-U) disables grouping''')
@click.option('-G', '--no-group', is_flag=True, help='in a long listing, don\'t print group names')
@click.option('-h', '--human-readable', is_flag=True, help='with -l and -s, print sizes like 1K 234M 2G etc.')
@click.option('--si', is_flag=True, help='likewise, but use powers of 1000 not 1024')
@click.option('-H', '--dereference-command-line', is_flag=True, help='follow symbolic links listed on the command line')
@click.option('--dereference-command-line-symlink-to-dir', is_flag=True,
              help='follow each command line symbolic link that points to a directory')
@click.option('--hide', multiple=True,
              help='do not list implied entries matching shell PATTERN (overridden by -a or -A)')
# Add hyperlink
@click.option('--indicator-style', type=click.Choice(list(INDICATOR_STYLE_NAMES.keys())),
              callback=lambda ctx, param, value: INDICATOR_STYLE_NAMES.get(value),
              help='append indicator with style WORD to entry names: none (default), slash (-p), file-type'
                   ' (--file-type), classify (-F)')
@click.option('-i', '--inode', is_flag=True, help='print the index number of each file')
@click.option('-I', '--ignore', multiple=True, help='do not list implied entries matching shell PATTERN')
# Add kibibytes
@click.option('-l', 'long', is_flag=True, help='use a long listing format')
@click.option('-L', '--dereference', is_flag=True,
              help='when showing file information for a symbolic link, show information for the file the link '
                   'references rather than for the link itself')
@click.option('-m', 'comma', is_flag=True, help='fill width with a comma separated list of entries')
@click.option('-n', '--numeric-uid-gid', is_flag=True, help='like -l, but list numeric user and group IDs')
@click.option('-N', '--literal', is_flag=True, help='print entry names without quoting')
@click.option('-o', 'owner_only', is_flag=True, help='like -l, but do not list group information')
@click.option('-p', 'indicator_slash', is_flag=True, help='append / indicator to directories')
# Add hide-control-chars
# Add show-control-chars
# Add quote-name
# Add quoting-style
@click.option('-r', '--reverse', is_flag=True, help='reverse order while sorting')
@click.option('-R', '--recursive', is_flag=True, help='list subdirectories recursively')
@click.option('-s', '--size', is_flag=True, help='print the allocated size of each file, in blocks')
@click.option('-S', 'size_sort', is_flag=True, help='sort by file size, largest first')
@click.option('--sort', type=click.Choice(list(SORT_TYPE_NAMES.keys())),
              callback=lambda ctx, param, value: SORT_TYPE_NAMES.get(value),
              help='sort by WORD instead of name: none (-U), size (-S), time (-t), version (-v), extension (-X)')
@click.option('--time', type=click.Choice(list(TIME_TYPE_NAMES.keys())),
              callback=lambda ctx, param, value: TIME_TYPE_NAMES.get(value),
              help=('''change the default of using modification times; access time (-u): atime, access, use;'''
                    ''' change time (-c): ctime, status; birth time: birth, creation;\n\n'''
                    '''with -l, WORD determines which time to show; with --sort=time, sort by WORD (newest first)'''))
@click.option('--time-style', type=click.Choice(list(TIME_STYLE_NAMES.keys())),
              callback=lambda ctx, param, value: TIME_STYLE_NAMES.get(value),
              help='time/date format with -l; see TIME_STYLE below')
@click.option('-t', 'time_sort', is_flag=True, help='sort by time, newest first; see --time')
@click.option('-T', '--tabsize', type=click.INT, help='assume tab stops at each COLS instead of 8')
@click.option('-u', 'atime', is_flag=True, help=('with -lt: sort by, and show, access time; with -l: show access time'
                                                 ' and sort by name; otherwise: sort by access time, newest first'))
@click.option('-U', 'unsort', is_flag=True, help='do not sort; list entries in directory order')
@click.option('-v', 'version_sort', is_flag=True, help='natural sort of (version) numbers within text')
@click.option('-w', '--width', type=click.INT, default=-1, help='set output width to COLS.  0 means no limit')
@click.option('-x', 'horizontal', is_flag=True, help='list entries by lines instead of by columns')
@click.option('-X', 'extension_sort', is_flag=True, help='sort alphabetically by entry extension')
# Add security context
@click.option('-1', 'one_per_line', is_flag=True, help='''list one file per line.  Avoid '\n' with -q or -b''')
@click.argument('files', nargs=-1)
def ls(files, all_, almost_all, author, block_size, ignore_backups, ctime, columns_format, directory, fast, classify,
       file_type, format_, full_time, group_only, group_directories_first, no_group, human_readable, si,
       dereference_command_line, dereference_command_line_symlink_to_dir, hide, indicator_style, inode, ignore, long,
       dereference, comma, numeric_uid_gid, literal, owner_only, indicator_slash, reverse, recursive, size, size_sort,
       sort, time, time_style, time_sort, tabsize, atime, unsort, version_sort, width, horizontal, extension_sort,
       one_per_line):
    Ls()(
        *files,
        all_=all_,
        almost_all=almost_all,
        author=author,
        block_size=block_size,
        ignore_backups=ignore_backups,
        ctime=ctime,
        columns_format=columns_format,
        directory=directory,
        fast=fast,
        classify=classify,
        file_type=file_type,
        format_=format_,
        full_time=full_time,
        group_only=group_only,
        group_directories_first=group_directories_first,
        no_group=no_group,
        human_readable=human_readable,
        si=si,
        dereference_command_line=dereference_command_line,
        dereference_command_line_symlink_to_dir=dereference_command_line_symlink_to_dir,
        hide=hide,
        indicator_style=indicator_style,
        inode=inode,
        ignore=ignore,
        long=long,
        dereference=dereference,
        comma=comma,
        numeric_uid_gid=numeric_uid_gid,
        literal=literal,
        owner_only=owner_only,
        indicator_slash=indicator_slash,
        reverse=reverse,
        recursive=recursive,
        size=size,
        size_sort=size_sort,
        sort=sort,
        time=time,
        time_style=time_style,
        time_sort=time_sort,
        tabsize=tabsize,
        atime=atime,
        unsort=unsort,
        version_sort=version_sort,
        width=width,
        horizontal=horizontal,
        extension_sort=extension_sort,
        one_per_line=one_per_line,
    )
