from __future__ import annotations

import sys

DATACLASS_KWARGS = {"slots": True} if sys.version_info >= (3, 10) else {}
UINT_VAR_MAX = 0x3FFFFFFFFFFFFFFF
UINT_VAR_MAX_SIZE = 8
