from bisect import bisect
from collections import namedtuple

from pykdebugparser.trace_handlers.perf import PerfEvent
from pykdebugparser.trace_handlers.dyld import DyldUuidMapA, DyldLaunchExecutable

Callstack = namedtuple('Callstack', ['timestamp', 'tid', 'frames'])
Frame = namedtuple('Frame', ['address', 'uuid', 'offset'])


class CallstacksParser:
    def __init__(self, dyld_addresses, dyld_uuids):
        self.dyld_addresses = dyld_addresses
        self.dyld_uuids = dyld_uuids

    def feed_generator(self, generator):
        for trace in generator:
            if isinstance(trace, PerfEvent) and trace.cs_frames is not None:
                frames = []
                for frame in trace.cs_frames:
                    index_ = bisect(self.dyld_addresses, frame) - 1
                    if index_ > -1:
                        frames.append(Frame(frame, self.dyld_uuids[index_], frame - self.dyld_addresses[index_]))
                    else:
                        frames.append(Frame(frame, None, None))
                yield Callstack(trace.ktraces[0].timestamp, trace.ktraces[0].tid, frames)
            elif isinstance(trace, DyldUuidMapA):
                self.insert_image(trace.load_addr, trace.uuid)
            elif isinstance(trace, DyldLaunchExecutable):
                for image in trace.uuid_map_a:
                    self.insert_image(image.load_addr, image.uuid)

    def insert_image(self, address, uuid):
        if address in self.dyld_addresses:
            return
        index_ = bisect(self.dyld_addresses, address)
        self.dyld_addresses.insert(index_, address)
        self.dyld_uuids.insert(index_, uuid)
