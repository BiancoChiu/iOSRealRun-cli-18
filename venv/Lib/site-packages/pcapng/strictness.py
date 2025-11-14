"""
Module for alerting the user when attempting to do things with pcapng that
aren't strictly valid.
"""

import warnings
from enum import Enum

from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning


class Strictness(Enum):
    NONE = 0  # No warnings, do what you want
    WARN = 1  # Do what you want, but warn of potential issues
    FIX = 2  # Warn of potential issues, fix *if possible*
    FORBID = 3  # raise exception on potential issues


strict_level = Strictness.FORBID


def set_strictness(level):
    assert type(level) is Strictness
    global strict_level
    strict_level = level


def problem(msg):
    "Warn or raise an exception with the given message."
    if strict_level == Strictness.FORBID:
        raise PcapngStrictnessError(msg)
    elif strict_level in (Strictness.WARN, Strictness.FIX):
        warnings.warn(PcapngStrictnessWarning(msg))


def warn(msg):
    "Show a warning with the given message."
    if strict_level > Strictness.NONE:
        warnings.warn(PcapngStrictnessWarning(msg))


def should_fix():
    "Helper function for showing code used to fix questionable pcapng data."
    return strict_level == Strictness.FIX
