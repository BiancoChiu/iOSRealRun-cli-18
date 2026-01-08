import fnmatch
import locale
import math
import os
import platform
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from functools import cmp_to_key
from itertools import chain
from stat import filemode, S_ISCHR, S_ISBLK, S_ISREG, S_IXUSR, S_IXGRP, S_IXOTH, S_ISDIR, S_ISLNK, S_ISFIFO, S_ISSOCK, \
    S_ISDOOR

try:

    import pwd
    import grp
    import termios
    import fcntl
except ImportError:
    # Not a unix based system.
    pwd = None
    grp = None
    termios = None
    fcntl = None

from pygnuutils.filevercmp import filevercmp
from pygnuutils.human_readable import parse_specs, human_readable as human_size, HumanReadableOption

SIX_MONTH_DELTA = timedelta(seconds=365.2425 * 24 * 60 * 60 / 2)
MIN_COLUMN_WIDTH = 3


class FileType(Enum):
    UNKNOWN = 0
    FIFO = auto()
    CHARDEV = auto()
    DIRECTORY = auto()
    BLOCKDEV = auto()
    NORMAL = auto()
    SYMBOLIC_LINK = auto()
    SOCK = auto()
    WHITEOUT = auto()
    ARG_DIRECTORY = auto()

    @classmethod
    def from_st_mode(cls, st_mode):
        _types_checks = {
            cls.BLOCKDEV: S_ISBLK,
            cls.CHARDEV: S_ISCHR,
            cls.DIRECTORY: S_ISDIR,
            cls.FIFO: S_ISFIFO,
            cls.SYMBOLIC_LINK: S_ISLNK,
            cls.NORMAL: S_ISREG,
            cls.SOCK: S_ISSOCK,
        }
        return [key for key, value in _types_checks.items() if value(st_mode)][0]


@dataclass
class FileInfo:
    name: str
    linkname: str = ''
    absolute_name: str = ''
    stat: os.stat_result = None
    filetype: FileType = FileType.UNKNOWN
    linkmode: int = 0
    scontext: str = ''

    def is_directory(self):
        return self.filetype in (FileType.DIRECTORY, FileType.ARG_DIRECTORY)

    def is_linked_directory(self):
        return self.is_directory() or S_ISDIR(self.linkmode)

    @property
    def stat_ok(self):
        return self.stat is not None


class Formats(Enum):
    LONG_FORMAT = 0
    ONE_PER_LINE = auto()
    MANY_PER_LINE = auto()
    HORIZONTAL = auto()
    WITH_COMMAS = auto()


class TimeStyle(Enum):
    FULL_ISO = 0
    LONG_ISO = auto()
    ISO = auto()
    LOCALE = auto()


class TimeType(Enum):
    MTIME = 0
    CTIME = auto()
    ATIME = auto()
    BTIME = auto()


class SortType(Enum):
    NAME = 0
    EXTENSION = auto()
    WIDTH = auto()
    SIZE = auto()
    VERSION = auto()
    TIME = auto()
    NONE = auto()


class IndicatorStyle(Enum):
    NONE = 0
    SLASH = auto()
    FILE_TYPE = auto()
    CLASSIFY = auto()


class WhenType(Enum):
    NEVER = 0
    ALWAYS = auto()
    IF_TTY = auto()


class DereferenceSymlink(Enum):
    UNDEFINED = 0
    NEVER = auto()
    COMMAND_LINE_ARGUMENTS = auto()
    COMMAND_LINE_SYMLINK_TO_DIR = auto()
    ALWAYS = auto()


class IgnoreMode(Enum):
    DEFAULT = 0
    DOT_AND_DOTDOT = auto()
    MINIMAL = auto()


class LsStub:
    @property
    def sep(self):
        return os.path.sep

    def join(self, path, *paths):
        return os.path.join(path, *paths)

    def abspath(self, path):
        return os.path.abspath(path)

    def stat(self, path, dir_fd=None, follow_symlinks=True):
        return os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def readlink(self, path, dir_fd=None):
        return os.readlink(path, dir_fd=dir_fd)

    def isabs(self, path):
        return os.path.isabs(path)

    def dirname(self, path):
        return os.path.dirname(path)

    def major(self, device):
        return os.major(device)

    def minor(self, device):
        return os.minor(device)

    def basename(self, path):
        return os.path.basename(path)

    def getgroup(self, st_gid):
        if grp is None:
            return '?'
        return grp.getgrgid(st_gid).gr_name

    def getuser(self, st_uid):
        if pwd is None:
            return '?'
        return pwd.getpwuid(st_uid).pw_name

    def now(self):
        return datetime.now()

    def listdir(self, path='.'):
        return os.listdir(path)

    def system(self):
        return platform.system()

    def getenv(self, key, default=None):
        return os.getenv(key, default)

    def isatty(self):
        return sys.stdout.isatty()

    def get_tty_width(self):
        if fcntl is None or termios is None:
            return 80
        cg_win_sz = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0))
        return struct.unpack('HHHH', cg_win_sz)[1]

    def setlocale(self, locale_setting=''):
        locale.setlocale(locale.LC_ALL, locale_setting)

    def print(self, *objects, sep=' ', end='\n', file=sys.stdout, flush=False):
        print(*objects, sep=sep, end=end, file=file, flush=flush)

    @property
    def st_nblocksize(self):
        return 4096

    def st_nblocks(self, stat):
        if hasattr(stat, 'st_blocks') and hasattr(stat, 'st_blksize'):
            size = stat.st_blocks * 512
        else:
            size = stat.st_size
        return size // self.st_nblocksize + int(size % self.st_nblocksize != 0)


@dataclass
class LsConfig:
    ignore_mode: IgnoreMode = IgnoreMode.DEFAULT
    print_author: bool = False
    output_block_size: int = 512
    human_output_opts: HumanReadableOption = HumanReadableOption(0)
    file_output_block_size: int = 1
    file_human_output_opts: HumanReadableOption = HumanReadableOption(0)
    ignore_patterns: list = field(default_factory=list)
    time_type: TimeType = TimeType.MTIME
    format: Formats = Formats.MANY_PER_LINE
    immediate_dirs: bool = False
    sort_type: SortType = SortType.NAME
    print_block_size: bool = False
    indicator_style: IndicatorStyle = IndicatorStyle.NONE
    print_owner: bool = True
    directories_first: bool = False
    print_group: bool = True
    dereference: DereferenceSymlink = DereferenceSymlink.UNDEFINED
    hide_patterns: list = field(default_factory=list)
    print_inode: bool = False
    numeric_ids: bool = False
    sort_reverse: bool = False
    recursive: bool = False
    print_scontext: bool = False
    tabsize: int = 0
    long_format_recent: str = '{0:%b} {0.day:2d} {0:%H:%M}'
    long_format_not_recent: str = '{0:%b} {0.day:2d}  {0:%Y}'
    line_length: int = 0

    @staticmethod
    def from_cli_params(stub: LsStub, all_=False, almost_all=False, author=False, block_size='', ignore_backups=False,
                        ctime=False, columns_format=False, directory=False, fast=False, classify=False, file_type=False,
                        format_: Formats = None, full_time=False, group_only=False, group_directories_first=False,
                        no_group=False, human_readable=False, si=False, dereference_command_line=False,
                        dereference_command_line_symlink_to_dir=False, hide=None,
                        indicator_style: IndicatorStyle = None, inode=False, ignore=None, long=False, dereference=False,
                        comma=False, numeric_uid_gid=False, literal=False, owner_only=False, indicator_slash=False,
                        reverse=False, recursive=False, size=False, size_sort=False, sort: SortType = None,
                        time: TimeType = None, time_style: TimeStyle = None, time_sort=False, tabsize=0, atime=False,
                        unsort=False, version_sort=False, width=-1, horizontal=False, extension_sort=False,
                        one_per_line=False):
        config = LsConfig()
        config.format = None
        config.print_author = author
        if all_:
            config.ignore_mode = IgnoreMode.MINIMAL
        if almost_all:
            config.ignore_mode = IgnoreMode.DOT_AND_DOTDOT
        if block_size:
            config.output_block_size, config.human_output_opts = parse_specs(block_size)
            if not config.output_block_size:
                config.output_block_size = 512 if stub.getenv('POSIXLY_CORRECT') else 1024
            config.file_output_block_size = config.output_block_size
            config.file_human_output_opts = config.human_output_opts
        if ignore_backups:
            config.ignore_patterns.append('*~')
            config.ignore_patterns.append('.*~')
        if ctime:
            config.time_type = TimeType.CTIME
        if columns_format:
            config.format = Formats.MANY_PER_LINE
        if directory:
            config.immediate_dirs = True
        if fast:
            config.ignore_mode = IgnoreMode.MINIMAL
            config.sort_type = SortType.NONE
            config.format = Formats.ONE_PER_LINE
            config.print_block_size = False
        if classify:
            config.indicator_style = IndicatorStyle.CLASSIFY
        if file_type:
            config.indicator_style = IndicatorStyle.FILE_TYPE
        if format_ is not None:
            config.format = format_
        if full_time:
            config.format = Formats.LONG_FORMAT
            time_style = TimeStyle.FULL_ISO
        if group_only:
            config.format = Formats.LONG_FORMAT
            config.print_owner = False
        if group_directories_first:
            config.directories_first = True
        if no_group:
            config.print_group = False
        if human_readable:
            config.file_human_output_opts = config.human_output_opts = (
                    HumanReadableOption.AUTOSCALE | HumanReadableOption.SI | HumanReadableOption.BASE_1024
            )
            config.file_output_block_size = config.output_block_size = 1
        if si:
            config.file_human_output_opts = config.human_output_opts = (
                    HumanReadableOption.AUTOSCALE | HumanReadableOption.SI
            )
            config.file_output_block_size = config.output_block_size = 1
        if dereference_command_line:
            config.dereference = DereferenceSymlink.COMMAND_LINE_ARGUMENTS
        if dereference_command_line_symlink_to_dir:
            config.dereference = DereferenceSymlink.COMMAND_LINE_SYMLINK_TO_DIR
        if hide is not None:
            config.hide_patterns.extend(hide)
        if indicator_style is not None:
            config.indicator_style = indicator_style
        if inode:
            config.print_inode = inode
        if ignore is not None:
            config.ignore_patterns.extend(ignore)
        if long:
            config.format = Formats.LONG_FORMAT
        if dereference:
            config.dereference = DereferenceSymlink.ALWAYS
        if comma:
            config.format = Formats.WITH_COMMAS
        if numeric_uid_gid:
            config.numeric_ids = True
            config.format = Formats.LONG_FORMAT
        if literal:
            # literal_quoting_style
            pass
        if owner_only:
            config.format = Formats.LONG_FORMAT
            config.print_group = False
        if indicator_slash:
            config.indicator_style = IndicatorStyle.SLASH
        if reverse:
            config.sort_reverse = True
        if recursive:
            config.recursive = True
        if size:
            config.print_block_size = True
        if size_sort:
            config.sort_type = SortType.SIZE
        if sort is not None:
            config.sort_type = sort
        if time is not None:
            config.time_type = time
        if time_sort:
            config.sort_type = SortType.TIME
        if tabsize:
            config.tabsize = tabsize
        if atime:
            config.time_type = TimeType.ATIME
        if unsort:
            config.sort_type = SortType.NONE
        if version_sort:
            config.sort_type = SortType.VERSION
        if horizontal:
            config.format = Formats.HORIZONTAL
        if extension_sort:
            config.sort_type = SortType.EXTENSION
        if one_per_line:
            config.format = Formats.ONE_PER_LINE

        if config.format is None:
            config.format = Formats.MANY_PER_LINE if stub.isatty() else Formats.ONE_PER_LINE

        if config.format in (Formats.MANY_PER_LINE, Formats.HORIZONTAL, Formats.WITH_COMMAS) and not config.tabsize:
            config.tabsize = 8

        if config.sort_type is None:
            config.sort_type = (
                SortType.TIME if config.format != Formats.LONG_FORMAT and config.time_type != TimeType.MTIME
                else SortType.NAME
            )
        LsConfig.load_time_style(config, time_style)
        if width < 0 and stub.isatty():
            width = stub.get_tty_width()

        config.line_length = width if width >= 0 else 80
        return config

    @staticmethod
    def load_time_style(config, time_style):
        if time_style is not None and config.format == Formats.LONG_FORMAT:
            if time_style == TimeStyle.FULL_ISO:
                config.long_format_not_recent = config.long_format_recent = '{0:%Y-%m-%d %H:%M:%S.%f %z}'
            if time_style == TimeStyle.LONG_ISO:
                config.long_format_not_recent = config.long_format_recent = '{0:%Y-%m-%d %H:%M}'
            if time_style == TimeStyle.ISO:
                config.long_format_not_recent = '{0:%Y-%m-%d} '
                config.long_format_recent = '{0:%m-%d %H:%M}'


class Ls:
    def __init__(self, stub=None):
        self.stub = LsStub() if stub is None else stub
        self.config = LsConfig()
        self.inode_number_width = 0
        self.block_size_width = 0
        self.nlink_width = 0
        self.scontext_width = 0
        self.owner_width = 0
        self.group_width = 0
        self.author_width = 0
        self.major_device_number_width = 0
        self.minor_device_number_width = 0
        self.file_size_width = 0
        self.print_with_color = False
        self.check_symlink_mode = False
        self.print_dir_name = True
        self.files = []
        self.pending_dirs = []
        self.active_dir_set = None
        self.max_idx = 0
        self.dev_ino_stack = []
        self.first_print_dir = True

    def run(self, *files, config=None):
        if config is not None:
            self.config = config
        self._reset_run_variables()
        self._run_on_input_files(files)

        if self.files:
            self._sort_files()
            if not self.config.immediate_dirs:
                self._extract_dirs_from_files('', True)

        if self.files:
            self._print_current_files()
            if self.pending_dirs:
                self.stub.print('')
        elif len(self.pending_dirs) == 1 and len(files) <= 1:
            self.print_dir_name = False

        self._run_on_dirs()

    # Methods related to the current run.

    def _reset_run_variables(self):
        self.stub.setlocale('')
        self.print_dir_name = True
        self.check_symlink_mode = self.config.directories_first
        self.files = []
        self.pending_dirs = []
        self.active_dir_set = set() if self.config.recursive else None
        self.max_idx = math.ceil(self.config.line_length / MIN_COLUMN_WIDTH)
        self.dev_ino_stack = []
        self.first_print_dir = True
        if self.config.dereference == DereferenceSymlink.UNDEFINED:
            if (self.config.immediate_dirs or self.config.indicator_style == IndicatorStyle.CLASSIFY or
                    self.config.format == Formats.LONG_FORMAT):
                self.config.dereference = DereferenceSymlink.NEVER
            else:
                self.config.dereference = DereferenceSymlink.COMMAND_LINE_SYMLINK_TO_DIR

    def _run_on_input_files(self, files):
        if not files:
            if self.config.immediate_dirs:
                self._gobble_file('.', FileType.DIRECTORY, True, '')
            else:
                self.pending_dirs.append(('.', '', True))
        else:
            for file in files:
                self._gobble_file(file, FileType.UNKNOWN, True, '')

    def _run_on_dirs(self):
        while self.pending_dirs:
            name, real_name, command_line_arg = self.pending_dirs.pop()
            if self.active_dir_set is not None and not name:
                di = self.dev_ino_stack.pop()
                self.active_dir_set.remove(di)
                continue
            self._print_dir(name, real_name, command_line_arg)
            self.print_dir_name = True

    # Methods related to iterating the current directory.

    def _clear_current_dir_files(self):
        self.files = []
        self.inode_number_width = 0
        self.block_size_width = 0
        self.nlink_width = 0
        self.owner_width = 0
        self.group_width = 0
        self.author_width = 0
        self.scontext_width = 0
        self.major_device_number_width = 0
        self.minor_device_number_width = 0
        self.file_size_width = 0

    def _print_dir(self, name, realname, command_line_arg):
        if self._stop_if_dir_visited(name):
            return
        self._clear_current_dir_files()
        if self.config.recursive or self.print_dir_name:
            if not self.first_print_dir:
                self.stub.print('')
            self.first_print_dir = False
            self.stub.print(f'{realname if realname else name}:')
        total_blocks = 0
        for entry_name in chain(('.', '..'), self.stub.listdir(name)):
            total_blocks += self._handle_current_dir_entry(entry_name, name)
        self._sort_files()
        if self.config.recursive:
            self._extract_dirs_from_files(name, False)
        if self.config.format == Formats.LONG_FORMAT or self.config.print_block_size:
            size = human_size(
                total_blocks, self.config.human_output_opts, self.stub.st_nblocksize, self.config.output_block_size
            )
            self.stub.print(f'total {size}')
        if self.files:
            self._print_current_files()

    def _stop_if_dir_visited(self, name):
        if self.active_dir_set is None:
            return False
        dir_stat = self.stub.stat(name, follow_symlinks=True)
        if (dir_stat.st_dev, dir_stat.st_ino) in self.active_dir_set:
            self.stub.print(f'ls: {name}: not listing already-listed directory')
            return True
        else:
            self.active_dir_set.add((dir_stat.st_dev, dir_stat.st_ino))
            self.dev_ino_stack.append((dir_stat.st_dev, dir_stat.st_ino))
            return False

    def _handle_current_dir_entry(self, entry_name, dir_name):
        if self._file_ignored(entry_name):
            return 0
        try:
            entry_stat = self.stub.stat(self.stub.join(dir_name, entry_name), follow_symlinks=False)
            d_type = FileType.from_st_mode(entry_stat.st_mode)
        except OSError:
            d_type = FileType.UNKNOWN
        total_blocks = self._gobble_file(entry_name, d_type, False, dir_name)
        if (self.config.format == Formats.ONE_PER_LINE and self.config.sort_type == SortType.NONE
                and not self.config.print_block_size and not self.config.recursive):
            self._print_current_files()
            self._clear_current_dir_files()
        return total_blocks

    def _extract_dirs_from_files(self, dirname, command_line_arg):
        if dirname and self.active_dir_set is not None:
            self.pending_dirs.append(('', dirname, False))
        for i in range(len(self.files) - 1, -1, -1):
            file = self.files[i]
            if file.is_directory() and (not dirname or not self.stub.basename(file.name) in ('.', '..')):
                if not dirname or file.name[0] == self.stub.sep:
                    self.pending_dirs.append((file.name, file.linkname, command_line_arg))
                else:
                    name = self.stub.join(dirname, file.name)
                    self.pending_dirs.append((name, file.linkname, command_line_arg))
                if file.filetype == FileType.ARG_DIRECTORY:
                    del self.files[i]

    def _sort_files(self):
        if self.config.sort_type == SortType.NONE:
            return
        if self.config.sort_type == SortType.TIME:
            sort_function = {
                TimeType.MTIME: lambda file: -file.stat.st_mtime if file.stat is not None else 0,
                TimeType.CTIME: lambda file: -file.stat.st_ctime if file.stat is not None else 0,
                TimeType.ATIME: lambda file: -file.stat.st_atime if file.stat is not None else 0,
                TimeType.BTIME: lambda file: -self._get_btime(file.stat) if file.stat is not None else 0,
            }[self.config.time_type]
        else:
            sort_function = {
                SortType.NAME: lambda file: locale.strxfrm(file.name),
                SortType.EXTENSION: lambda file: file.name.split('.')[-1] if '.' in file.name else '',
                SortType.WIDTH: lambda file: -len(file.name),
                SortType.SIZE: lambda file: -file.stat.st_size if file.stat is not None else 0,
                SortType.VERSION: cmp_to_key(lambda file1, file2: filevercmp(file1.name, file2.name)),
            }[self.config.sort_type]
        self.files.sort(key=sort_function, reverse=self.config.sort_reverse)
        if self.config.directories_first:
            self.files.sort(key=lambda file: file.is_linked_directory(), reverse=True)

    # Methods related to iterating a specific file.

    def _gobble_file(self, name: str, type_: FileType, command_line_arg: bool, dirname: str):
        file_info = FileInfo(name)
        file_info.filetype = type_
        if name[0] != self.stub.sep and dirname:
            name = self.stub.join(dirname, name)

        file_info.absolute_name = self.stub.abspath(name)

        try:
            file_info.stat = self._stat_with_dereference_config(name, command_line_arg)
        except OSError as e:
            self.stub.print(f'ls: cannot access \'{name}\': {e.strerror}')
            if not command_line_arg:
                self.files.append(file_info)
            return 0

        self._add_symlink_mode(file_info, name)
        self._add_file_type(file_info, command_line_arg)

        if self.config.format == Formats.LONG_FORMAT or self.config.print_block_size:
            size = human_size(self.stub.st_nblocks(file_info.stat), self.config.human_output_opts,
                              self.stub.st_nblocksize, self.config.output_block_size)
            self.block_size_width = max(self.block_size_width, len(size))
        if self.config.format == Formats.LONG_FORMAT:
            self._gobble_long_format(file_info)
        if self.config.print_inode:
            self.inode_number_width = max(self.inode_number_width, len(str(file_info.stat.st_ino)))

        self.files.append(file_info)
        return self.stub.st_nblocks(file_info.stat)

    def _stat_with_dereference_config(self, name, command_line_arg):
        if self.config.dereference == DereferenceSymlink.ALWAYS:
            do_deref = True
        elif self.config.dereference == DereferenceSymlink.COMMAND_LINE_ARGUMENTS:
            do_deref = command_line_arg
        elif self.config.dereference == DereferenceSymlink.COMMAND_LINE_SYMLINK_TO_DIR:
            do_deref = command_line_arg and S_ISDIR(self.stub.stat(name).st_mode)
        else:
            do_deref = False
        return self.stub.stat(name, follow_symlinks=do_deref)

    def _add_symlink_mode(self, file_info, name):
        if S_ISLNK(file_info.stat.st_mode) and (self.config.format == Formats.LONG_FORMAT or self.check_symlink_mode):
            file_info.linkname = self.stub.readlink(name)
            link_name = file_info.linkname
            if not self.stub.isabs(file_info.linkname):
                link_name = self.stub.join(self.stub.dirname(name), file_info.linkname)
            if link_name and (self.check_symlink_mode or self.config.indicator_style != IndicatorStyle.NONE):
                file_info.linkmode = self.stub.stat(link_name).st_mode

    def _add_file_type(self, file_info, command_line_arg):
        if S_ISLNK(file_info.stat.st_mode):
            file_info.filetype = FileType.SYMBOLIC_LINK
        elif S_ISDIR(file_info.stat.st_mode):
            file_info.filetype = (
                FileType.ARG_DIRECTORY if command_line_arg and not self.config.immediate_dirs else FileType.DIRECTORY
            )
        else:
            file_info.filetype = FileType.NORMAL

    def _gobble_long_format(self, file_info):
        if self.config.print_owner:
            self.owner_width = max(self.owner_width, len(self._format_user(file_info.stat)))
        if self.config.print_group:
            self.group_width = max(self.group_width, len(self._format_group(file_info.stat)))
        if self.config.print_author:
            # Use st_uid since there isn't ant st_author in python.
            self.author_width = max(self.author_width, len(self._format_user(file_info.stat)))

        self.nlink_width = max(self.nlink_width, len(f'{file_info.stat.st_nlink:d}'))

        if S_ISCHR(file_info.stat.st_mode) or S_ISBLK(file_info.stat.st_mode):
            major = self.stub.major(file_info.stat.st_rdev)
            self.major_device_number_width = max(self.major_device_number_width, len(f'{major:d}'))
            minor = self.stub.minor(file_info.stat.st_rdev)
            self.minor_device_number_width = max(self.minor_device_number_width, len(f'{minor:d}'))
            length = self.major_device_number_width + self.minor_device_number_width + 2
            self.file_size_width = max(self.file_size_width, length)
        else:
            size_length = len(human_size(
                file_info.stat.st_size, self.config.file_human_output_opts,
                to_block_size=self.config.file_output_block_size
            ))
            self.file_size_width = max(self.file_size_width, size_length)

    def _file_ignored(self, name: str):
        for pattern in self.config.ignore_patterns:
            if fnmatch.fnmatch(name, pattern):
                return True

        if self.config.ignore_mode == IgnoreMode.DEFAULT:
            for pattern in self.config.hide_patterns:
                if fnmatch.fnmatch(name, pattern):
                    return True

        if self.config.ignore_mode == IgnoreMode.MINIMAL:
            return False
        if self.config.ignore_mode == IgnoreMode.DOT_AND_DOTDOT:
            return name in ('.', '..')
        if self.config.ignore_mode == IgnoreMode.DEFAULT:
            return name.startswith('.')

    def _get_btime(self, stat):
        if hasattr(stat, 'st_birthtime'):
            return stat.st_birthtime
        elif 'windows' in self.stub.system().lower():
            return stat.st_ctime
        return 0

    # Methods related to formatting and printing.

    def _print_current_files(self):
        if self.config.format == Formats.ONE_PER_LINE:
            for file in self.files:
                self.stub.print(self._format_file_name_and_frills(file))
        elif self.config.format == Formats.MANY_PER_LINE:
            if not self.config.line_length:
                self._print_with_separator(' ')
            else:
                self._print_many_per_line()
        elif self.config.format == Formats.HORIZONTAL:
            if not self.config.line_length:
                self._print_with_separator(' ')
            else:
                self._print_horizontal()
        elif self.config.format == Formats.WITH_COMMAS:
            self._print_with_separator(',')
        elif self.config.format == Formats.LONG_FORMAT:
            for file in self.files:
                self._print_long_format(file)

    def _print_with_separator(self, sep):
        pos = 0
        data = ''
        for file in self.files:
            formatted = self._format_file_name_and_frills(file)
            if not data:
                data = formatted
                pos = len(formatted)
            elif self.config.line_length and (pos + len(formatted) + 2) >= self.config.line_length:
                data += f'{sep}\n{formatted}'
                pos = len(formatted)
            else:
                data += f'{sep} {formatted}'
                pos += len(formatted) + 2
        self.stub.print(data)

    def _print_many_per_line(self):
        cols, column_info = self._calculate_columns(True)
        rows = math.ceil(len(self.files) / (cols + 1))
        for row in range(rows):
            f = row
            i = 0
            from_ = 0
            while f < len(self.files):
                file = self.files[f]
                self.stub.print(
                    self._indent(self._format_file_name_and_frills(file), from_, from_ + column_info[i]), end=''
                )
                from_ += column_info[i]
                f += rows
                i += 1
            self.stub.print('')

    def _print_horizontal(self):
        cols, column_info = self._calculate_columns(False)
        pos = 0
        for filesno, file in enumerate(self.files):
            col = filesno % cols
            indented = self._indent(self._format_file_name_and_frills(file), pos, pos + column_info[col])
            if col == cols - 1 and filesno != len(self.files) - 1:
                self.stub.print(indented)
                pos = 0
            else:
                self.stub.print(indented, end='')
                pos += column_info[col]
        self.stub.print('')

    def _print_long_format(self, file: FileInfo):
        stat = file.stat
        modebuf = filemode(stat.st_mode) if stat is not None else '?pcdb-lswd'[file.filetype.value].ljust(10, '?')
        print_buf = self._format_inode(stat)
        print_buf += self._format_block_size(stat)
        print_buf += f'''{modebuf} {stat.st_nlink if stat is not None else '?':>{self.nlink_width}} '''
        # print_owner || print_group || print_author || print_scontext
        fill_direction = '>' if self.config.numeric_ids and stat is not None else '<'
        if self.config.print_owner:
            print_buf += f'{self._format_user(stat):{fill_direction}{self.owner_width}s} '
        if self.config.print_group:
            print_buf += f'{self._format_group(stat):{fill_direction}{self.group_width}s} '
        if self.config.print_author:
            print_buf += f'{self._format_user(stat):{fill_direction}{self.author_width}s} '
        if stat is not None and (S_ISCHR(stat.st_mode) or S_ISBLK(stat.st_mode)):
            blanks_width = self.file_size_width - self.major_device_number_width - self.minor_device_number_width - 2
            major_pad = self.major_device_number_width + max(0, blanks_width)
            print_buf += (f'{self.stub.major(stat.st_rdev):>{major_pad}d}, '
                          f'{self.stub.minor(stat.st_rdev):>{self.minor_device_number_width}d} ')
        else:
            size = '?' if stat is None else human_size(file.stat.st_size, self.config.file_human_output_opts,
                                                       to_block_size=self.config.file_output_block_size)
            print_buf += f'{size:>{self.file_size_width}s} '
        print_buf += self._format_long_time(stat)
        # TODO: quotes
        print_buf += file.name
        if file.filetype == FileType.SYMBOLIC_LINK and file.linkname:
            print_buf += f' -> {file.linkname}{self._format_type_indicator(True, file.linkmode, FileType.UNKNOWN)}'
        else:
            print_buf += self._format_type_indicator(
                stat is not None,
                stat.st_mode if stat is not None else 0, file.filetype)
        self.stub.print(print_buf)

    def _indent(self, formatted_data, from_, to):
        pad = ''
        from_ += len(formatted_data)
        while from_ < to:
            if self.config.tabsize and to // self.config.tabsize > (from_ + 1) // self.config.tabsize:
                pad += '\t'
                from_ += self.config.tabsize - from_ % self.config.tabsize
            else:
                pad += ' '
                from_ += 1
        return formatted_data + pad

    def _calculate_columns(self, by_columns):
        max_cols = self.max_idx if self.max_idx and self.max_idx < len(self.files) else len(self.files)
        column_info = [[MIN_COLUMN_WIDTH for _ in range(self.max_idx * (self.max_idx + 1) // 2)] for _ in
                       range(max_cols)]
        line_lengths = [(i + 1) * MIN_COLUMN_WIDTH for i in range(max_cols)]
        for f, file in enumerate(self.files):
            name_length = len(self._format_file_name_and_frills(file))
            for i in range(max_cols):
                idx = (f // ((len(self.files) + 1) // (i + 1))) if by_columns else f % (i + 1)
                real_length = name_length
                if idx != i:  # last column
                    real_length += 2
                if column_info[i][idx] < real_length:
                    line_lengths[i] += real_length - column_info[i][idx]
                    column_info[i][idx] = real_length

        cols = max_cols - 1
        for col in range(max_cols - 1, -1, -1):
            if line_lengths[col] < self.config.line_length:
                cols = col
                break

        return cols, column_info[cols if by_columns else cols - 1]

    def _format_group(self, stat):
        if stat is None:
            return '?'
        return str(stat.st_gid) if self.config.numeric_ids else self.stub.getgroup(stat.st_gid)

    def _format_user(self, stat):
        if stat is None:
            return '?'
        return str(stat.st_uid) if self.config.numeric_ids else self.stub.getuser(stat.st_uid)

    def _format_file_name_and_frills(self, file: FileInfo):
        print_buf = self._format_inode(file.stat)
        print_buf += self._format_block_size(file.stat)
        print_buf += file.name
        print_buf += self._format_type_indicator(file.stat_ok, file.stat.st_mode if file.stat_ok else 0, file.filetype)
        return print_buf

    def _format_inode(self, stat):
        if not self.config.print_inode:
            return ''
        length = 0 if self.config.format == Formats.WITH_COMMAS else self.inode_number_width
        inode = str(stat.st_ino) if stat is not None and stat.st_ino else '?'
        return f'{inode:>{length}s} '

    def _format_block_size(self, stat):
        if not self.config.print_block_size:
            return ''
        length = 0 if self.config.format == Formats.WITH_COMMAS else self.block_size_width
        size = '?' if stat is None else human_size(self.stub.st_nblocks(stat), self.config.human_output_opts,
                                                   self.stub.st_nblocksize, self.config.output_block_size)
        return f'{size:>{length}s} '

    def _format_long_time(self, stat):
        if stat is None:
            return '?'.rjust(len(self.stub.now().strftime(self.config.long_format_recent))) + ' '
        if self.config.time_type == TimeType.CTIME:
            when_timespec = datetime.fromtimestamp(stat.st_ctime)
        elif self.config.time_type == TimeType.MTIME:
            when_timespec = datetime.fromtimestamp(stat.st_mtime)
        elif self.config.time_type == TimeType.ATIME:
            when_timespec = datetime.fromtimestamp(stat.st_atime)
        elif self.config.time_type == TimeType.BTIME and self._get_btime(stat):
            when_timespec = datetime.fromtimestamp(self._get_btime(stat))
        else:
            raise ValueError()
        recent = when_timespec > self.stub.now() - SIX_MONTH_DELTA
        time_format = self.config.long_format_recent if recent else self.config.long_format_not_recent
        time_str = time_format.format(when_timespec)
        return f'{time_str} '

    def _format_type_indicator(self, stat_ok, mode, filetype):
        if self.config.indicator_style == IndicatorStyle.NONE:
            return ''
        if S_ISREG(mode) if stat_ok else filetype == FileType.NORMAL:
            if stat_ok and self.config.indicator_style == IndicatorStyle.CLASSIFY and mode & (
                    S_IXUSR | S_IXGRP | S_IXOTH):
                return '*'
            else:
                return ''
        if S_ISDIR(mode) if stat_ok else filetype in (FileType.DIRECTORY, FileType.ARG_DIRECTORY):
            return '/'
        elif self.config.indicator_style == IndicatorStyle.SLASH:
            return ''
        elif S_ISLNK(mode) if stat_ok else filetype == FileType.SYMBOLIC_LINK:
            return '@'
        elif S_ISFIFO(mode) if stat_ok else filetype == FileType.FIFO:
            return '|'
        elif S_ISSOCK(mode) if stat_ok else filetype == FileType.SOCK:
            return '='
        elif stat_ok and S_ISDOOR(mode):
            return '>'
        return ''

    def __call__(self, *files, all_=False, almost_all=False, author=False, block_size='', ignore_backups=False,
                 ctime=False, columns_format=False, directory=False, fast=False, classify=False, file_type=False,
                 format_: Formats = None, full_time=False, group_only=False, group_directories_first=False,
                 no_group=False, human_readable=False, si=False, dereference_command_line=False,
                 dereference_command_line_symlink_to_dir=False, hide=None, indicator_style: IndicatorStyle = None,
                 inode=False, ignore=None, long=False, dereference=False, comma=False, numeric_uid_gid=False,
                 literal=False, owner_only=False, indicator_slash=False, reverse=False, recursive=False, size=False,
                 size_sort=False, sort: SortType = None, time: TimeType = None, time_style: TimeStyle = None,
                 time_sort=False, tabsize=0, atime=False, unsort=False, version_sort=False, width=-1, horizontal=False,
                 extension_sort=False, one_per_line=False):
        config = LsConfig.from_cli_params(
            self.stub,
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
        self.run(*files, config=config)
