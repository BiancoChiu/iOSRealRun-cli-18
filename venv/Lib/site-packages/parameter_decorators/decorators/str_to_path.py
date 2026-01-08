from inspect import Parameter
from pathlib import Path
from typing import Any

from parameter_decorators.common import create_decorator
from parameter_decorators.decoration_interface import DecorationInterface

__all__ = ['str_to_path']


class StrToPath(DecorationInterface):
    def validate(self, param: Any, signature_item: Parameter) -> bool:
        return signature_item.annotation == Path and isinstance(param, str)

    def convert(self, param: Any, signature_item: Parameter) -> Any:
        return Path(param)

    def reannotation_validate(self, signature_item: Parameter) -> bool:
        return signature_item.annotation == Path

    def reannotate(self, signature_item: Parameter) -> Any:
        return str


def str_to_path(*params, reannotate: bool = True):
    """
    Decorator for converting string parameters to path.
    :param params: List of parameters names to convert, omit to convert all.
    :param reannotate: Whether to change the function annotation.
    """
    return create_decorator(params, StrToPath(), reannotate)
