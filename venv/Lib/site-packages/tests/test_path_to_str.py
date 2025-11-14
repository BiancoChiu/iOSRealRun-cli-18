import os.path
from pathlib import Path

from parameter_decorators import path_to_str


def test_sanity():
    @path_to_str()
    def function(a: str, b):
        assert isinstance(a, str)
        assert isinstance(b, Path)

    function(Path('asd'), Path('asd'))


def test_explicit():
    @path_to_str('a')
    def function(a, b: str):
        assert isinstance(a, str)
        assert isinstance(b, Path)

    function(Path('asd'), Path('asd'))


def test_already_str():
    @path_to_str()
    def function(a: str):
        assert isinstance(a, str)

    function('asd')


def test_expanduser():
    @path_to_str('a', expanduser=True)
    def function(a):
        assert isinstance(a, str)
        assert a == str(Path.home() / 'subdir')

    function(Path('~/subdir'))


def test_expanduser_already_str():
    @path_to_str('a', expanduser=True)
    def function(a):
        assert isinstance(a, str)
        assert a == str(Path.home() / 'subdir')

    function('~/subdir')


def test_expanduser_not_expandable():
    @path_to_str('a', expanduser=True)
    def function(a):
        assert isinstance(a, str)
        assert a == os.path.join('a', 'subdir')

    function(Path('a/subdir'))
