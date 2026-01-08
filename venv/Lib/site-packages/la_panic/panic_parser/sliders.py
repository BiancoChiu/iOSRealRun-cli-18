import click

from typing import Optional

from la_panic.data_structure.raw_crash_stack import RawCrashStack, ValueNotExistInStack


class KernelSliders(object):
    __kernel_text_exec_base: Optional[hex] = None
    __kernel_text_exec_slide: Optional[hex] = None
    __kernel_text_base: Optional[hex] = None
    __kernel_slide: Optional[hex] = None
    __kernel_cache_base: Optional[hex] = None
    __kernel_cache_slide: Optional[hex] = None

    def __init__(self, panic_infos: RawCrashStack):
        try:
            value_index = panic_infos.search_first_appearance("KernelCache slide")
            self.__kernel_cache_slide = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        try:
            value_index = panic_infos.search_first_appearance("KernelCache base")
            self.__kernel_cache_base = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        try:
            value_index = panic_infos.search_first_appearance("Kernel slide")
            self.__kernel_slide = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        try:
            value_index = panic_infos.search_first_appearance("Kernel text slide")
            self.__kernel_text_slide = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        try:
            value_index = panic_infos.search_first_appearance("Kernel text base")
            self.__kernel_text_base = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        try:
            value_index = panic_infos.search_first_appearance("Kernel text exec slide")
            self.__kernel_text_exec_slide = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        try:
            value_index = panic_infos.search_first_appearance("Kernel text exec base")
            self.__kernel_text_exec_base = panic_infos.value_in_index(value_index).rsplit(":", 1)[1].strip()
        except ValueNotExistInStack:
            pass

        panic_infos.pop_until_line_containing("mach_absolute_time")

    def json(self):
        return f"""{{
        "kernel_slide": \"{self.__kernel_slide}\",
        "kernel_cache_base": \"{self.__kernel_cache_base}\",
        "kernel_cache_slide": \"{self.__kernel_cache_slide}\",
        "kernel_text_base": \"{self.__kernel_text_base}\",
        "kernel_text_exec_base": \"{self.__kernel_text_exec_base}\",
        "kernel_text_exec_slide": \"{self.__kernel_text_exec_slide}\"
    }}"""

    def __repr__(self):
        description = ""

        if self.__kernel_slide:
            description += click.style(f"\tKernel Slide: 0x{int(self.__kernel_slide, 16):016x}\n")
        else:
            description += click.style("\tKernel Slide: None\n")

        if self.__kernel_text_base:
            description += click.style(f"\tKernel Text Base: 0x{int(self.__kernel_text_base, 16):016x}\n")
        else:
            description += click.style("\tKernel Text Base: None\n")

        if self.__kernel_text_exec_base:
            description += click.style(f"\tKernel Text Exec Base: 0x{int(self.__kernel_text_exec_base, 16):016x}\n")
        else:
            description += click.style("\tKernel Text Exec Base: None\n")

        if self.__kernel_text_exec_slide:
            description += click.style(f"\tKernel Text Exec Slide: 0x{int(self.__kernel_text_exec_slide, 16):016x}\n")
        else:
            description += click.style("\tKernel Text Exec Slide: None\n")

        if self.__kernel_cache_base:
            description += click.style(f"\tKernel Cache Base: 0x{int(self.__kernel_cache_base, 16):016x}\n")
        else:
            description += click.style("\tKernel Cache Base: None")

        if self.__kernel_cache_slide:
            description += click.style(f"\tKernel Cache Slide: 0x{int(self.__kernel_cache_slide, 16):016x}\n")
        else:
            description += click.style("\tKernel Cache Slide: None")

        return description

    def __str__(self):
        return self.__repr__()

    @property
    def kernel_slide(self) -> Optional[hex]:
        return self.__kernel_slide

    @property
    def kernel_cache_slide(self):
        if self.__kernel_cache_slide:
            return self.__kernel_cache_slide

        if self.__kernel_slide:
            return self.__kernel_slide
