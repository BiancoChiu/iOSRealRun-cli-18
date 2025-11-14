from abc import ABC, abstractmethod
from inspect import Parameter
from typing import Any


class DecorationInterface(ABC):
    @abstractmethod
    def validate(self, param: Any, signature_item: Parameter) -> bool:
        return False

    @abstractmethod
    def convert(self, param: Any, signature_item: Parameter) -> Any:
        return None

    @abstractmethod
    def reannotation_validate(self, signature_item: Parameter) -> bool:
        return False

    @abstractmethod
    def reannotate(self, signature_item: Parameter) -> Any:
        return None
