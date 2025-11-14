import sys

if sys.platform == 'win32':
    from .wintun import TunTapDevice  # noqa: F401
elif sys.platform == 'darwin':
    from .darwin import TunTapDevice  # noqa: F401
else:
    from .linux import TunTapDevice  # noqa: F401
