import pytest

from pykdebugparser.callstacks_parser import CallstacksParser
from pykdebugparser.trace_codes import default_trace_codes
from pykdebugparser.traces_parser import TracesParser


@pytest.fixture(scope='function')
def traces_parser():
    return TracesParser(default_trace_codes(), {}, {})


@pytest.fixture(scope='function')
def callstacks_parser():
    return CallstacksParser([], [])
