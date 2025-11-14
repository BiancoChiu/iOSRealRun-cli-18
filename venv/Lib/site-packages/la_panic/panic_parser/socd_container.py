import click

from typing import Mapping, Any


class SOCDContainer(object):
    __panic_string: str
    __data: bytes

    def __init__(self, json: Mapping[str, Any]):
        # This seems like base64, but decoding it gave a weird byte stream..
        # Leaving it as is
        self.__data = json.get('SOCDContainer')
        self.__panic_string = json.get('SOCDPanicString')

    def __repr__(self):
        description = ""

        description += click.style("\tConatiner:\n\t\t")
        for count, char in enumerate(self.__data):
            if count % 100 == 0:
                description += click.style("\n\t\t")

            description += click.style(f"{char}")

        description += click.style("\n\n")
        description += click.style(f"\t\tPanic:\n\n\t\t{self.__panic_string}\n")

        return description

    def __str__(self):
        return self.__repr__()
