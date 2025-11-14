import os
from inspect import Parameter
from pathlib import Path
from typing import Any

from parameter_decorators.common import create_decorator
from parameter_decorators.decoration_interface import DecorationInterface

__all__ = ['path_to_str']


class PathToStr(DecorationInterface):
    def __init__(self, expanduser):
        self.expanduser = expanduser

    def validate(self, param: Any, signature_item: Parameter) -> bool:
        return signature_item.annotation == str and isinstance(param, Path)

    def convert(self, param: Any, signature_item: Parameter) -> Any:
        if self.expanduser:
            param = Path(param).expanduser()
        return str(param)

    def reannotation_validate(self, signature_item: Parameter) -> bool:
        return signature_item.annotation == str

    def reannotate(self, signature_item: Parameter) -> Any:
        return os.PathLike


def path_to_str(*params, expanduser: bool = False, reannotate: bool = True):
    """
    Decorator for converting path parameters to string.
    :param params: List of parameters names to convert, omit to convert all.
    :param expanduser: Whether to expand decorated paths.
    :param reannotate: Whether to change the function annotation.
    """
    return create_decorator(params, PathToStr(expanduser), reannotate)
