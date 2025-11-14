from pykdebugparser.trace_codes import from_trace_codes_text

import pytest


@pytest.mark.parametrize('text, out', [
    ('0x40c0548	BSC_stat64', {0x40c0548: 'BSC_stat64'}),
    (('0x80010068 ASPCORE_PUSH_PAGES                                          		'
      '#Params: flow band page size		#Matchby: Arg1'), {0x80010068: 'ASPCORE_PUSH_PAGES'}),
    ('0x40c0548	BSC_stat64\n0x40c054c	BSC_sys_fstat64', {0x40c0548: 'BSC_stat64', 0x40c054c: 'BSC_sys_fstat64'}),
])
def test_from_trace_codes_text(text, out):
    assert from_trace_codes_text(text) == out
