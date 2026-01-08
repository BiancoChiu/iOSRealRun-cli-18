import sys


class YesStub:
    def print(self, *objects, sep=' ', end='\n', file=sys.stdout, flush=False):
        print(*objects, sep=sep, end=end, file=file, flush=flush)


class Yes:
    def __init__(self, stub=None):
        self.stub = YesStub() if stub is None else stub

    def run(self, *operands):
        buf = ' '.join(operands) if operands else 'y'
        try:
            while True:
                self.stub.print(buf)
        except KeyboardInterrupt:
            pass

    def __call__(self, *operands):
        self.run(*operands)
