import sys

from pathlib import PurePath


class BasenameStub:
    def base_name(self, name):
        return PurePath(name).parts[-1]

    def print(self, *objects, sep=' ', end='\n', file=sys.stdout, flush=False):
        print(*objects, sep=sep, end=end, file=file, flush=flush)


class Basename:
    def __init__(self, stub=None):
        self.stub = BasenameStub() if stub is None else stub

    def run(self, *names, suffix='', use_nuls=False):
        for name in names:
            name = self.stub.base_name(name)
            if name.endswith(suffix) and suffix:
                name = name[:-len(suffix)]
            self.stub.print(name, end='\x00' if use_nuls else '\n')

    def __call__(self, *name, multiple=False, suffix='', zero=False):
        if suffix:
            multiple = True
        if multiple:
            self.run(*name, suffix=suffix, use_nuls=zero)
        else:
            suffix = name[1] if len(name) > 1 else ''
            self.run(name[0], suffix=suffix, use_nuls=zero)
