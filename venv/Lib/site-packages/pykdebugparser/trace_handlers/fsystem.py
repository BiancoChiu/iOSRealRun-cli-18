from dataclasses import dataclass
from typing import List


@dataclass
class VfsLookup:
    ktraces: List
    path: str
    vnode_id: int

    def __str__(self):
        return f'lookup("{self.path}"), vnode id: {self.vnode_id}'


def handle_vfs_lookup(parser, events):
    node = parser.parse_vnode(events)
    return VfsLookup(events, node.path, node.vnode_id)


handlers = {
    'VFS_LOOKUP': handle_vfs_lookup,
}
