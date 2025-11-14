from pathlib import Path

from parameter_decorators import str_to_path


def test_sanity():
    @str_to_path()
    def function(a: Path, b):
        assert isinstance(a, Path)
        assert a == Path('asd')
        assert isinstance(b, str)
        assert b == 'asd'

    function('asd', 'asd')


def test_explicit():
    @str_to_path('a')
    def function(a, b: str):
        assert isinstance(a, Path)
        assert isinstance(b, str)

    function('asd', 'asd')


def test_already_path():
    @str_to_path()
    def function(a: Path):
        assert isinstance(a, Path)

    function(Path('asd'))
