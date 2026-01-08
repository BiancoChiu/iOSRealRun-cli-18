from importlib.metadata import version

from .errors import *  # noqa: F403
from .parser import *  # noqa: F403
from .types import *  # noqa: F403

__version__ = version(__package__)
