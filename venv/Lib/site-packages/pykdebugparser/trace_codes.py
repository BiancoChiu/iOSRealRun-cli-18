from typing import Mapping
from pathlib import Path


def from_trace_codes_text(codes_text: str) -> Mapping[int, str]:
    """
    Convert a trace codes text to dictionary.
    :param codes_text: Trace codes file data.
    :return: Mapping between code and event name.
    """
    return {int(s[0], 16): s[1] for s in map(lambda l: l.split(), codes_text.splitlines())}


def from_trace_codes_file(path: str) -> Mapping[int, str]:
    """
    Read trace codes from a file.
    :param path: Trace codes file path.
    :return: Mapping between code and event name.
    """
    with open(path, 'r') as fd:
        return from_trace_codes_text(fd.read())


def default_trace_codes() -> Mapping[int, str]:
    """
    Get the default trace codes mapping.
    :return: Mapping between code and event name.
    """
    with open(Path(__file__).resolve().parent.joinpath('trace.codes'), 'r') as fd:
        return from_trace_codes_text(fd.read())
