from typing import Optional, Iterable, Any, Union, Callable, List

import inquirer3.questions as questions
from inquirer3.render.console import ConsoleRender


def text(
    message: Any,
    default: Optional[str] = None,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    show_default: Union[bool, Callable] = False,
    trim_header: bool = True,
    autocomplete: Optional[Callable] = None,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.Text(
        name="",
        message=message,
        default=default,
        ignore=ignore,
        validate=validate,
        show_default=show_default,
        autocomplete=autocomplete,
        trim_header=trim_header,
    )
    return render.render(question)


def editor(
    message: Any,
    default: Optional[str] = None,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    show_default: Union[bool, Callable] = False,
    trim_header: bool = True,
    autocomplete: Optional[Callable] = None,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.Editor(
        name="",
        message=message,
        default=default,
        ignore=ignore,
        validate=validate,
        show_default=show_default,
        autocomplete=autocomplete,
        trim_header=trim_header,
    )
    return render.render(question)


def password(
    message: Any,
    echo: str = "*",
    default: Any = None,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    show_default: Union[bool, Callable] = False,
    trim_header: Union[bool, Callable] = True,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.Password(
        name="",
        message=message,
        echo=echo,
        default=default,
        ignore=ignore,
        validate=validate,
        show_default=show_default,
        trim_header=trim_header,
    )
    return render.render(question)


def confirm(
    message: Any = "",
    default: Any = False,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    trim_header: Union[bool, Callable] = True,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.Confirm(
        name="",
        message=message,
        default=default,
        ignore=ignore,
        validate=validate,
        trim_header=trim_header,
    )
    return render.render(question)


def list_input(
    choices: Iterable,
    message: Any = "",
    default: Any = None,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    show_default: Union[bool, Callable] = False,
    other: bool = False,
    trim_header: Union[bool, Callable] = True,
    carousel: bool = False,
    autocomplete: Optional[Callable] = None,
    trim_choices: bool = False,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.List(
        name="",
        choices=choices,
        message=message,
        default=default,
        ignore=ignore,
        validate=validate,
        show_default=show_default,
        other=other,
        trim_header=trim_header,
        carousel=carousel,
        autocomplete=autocomplete,
        trim_choices=trim_choices,
    )
    return render.render(question)


def checkbox(
    choices: Iterable,
    message: Any = "",
    default: Any = None,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    show_default: Union[bool, Callable] = False,
    other: bool = False,
    trim_header: Union[bool, Callable] = True,
    locked: Optional[List] = None,
    carousel: bool = False,
    autocomplete: Optional[Callable] = None,
    trim_choices: bool = False,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.Checkbox(
        name="",
        choices=choices,
        message=message,
        default=default,
        ignore=ignore,
        validate=validate,
        show_default=show_default,
        other=other,
        trim_header=trim_header,
        locked=locked,
        carousel=carousel,
        autocomplete=autocomplete,
        trim_choices=trim_choices,
    )
    return render.render(question)


def path(
    message: Any = "",
    default: Any = None,
    ignore: Union[bool, Callable] = False,
    validate: Union[bool, Callable] = True,
    show_default: Union[bool, Callable] = False,
    trim_header: Union[bool, Callable] = True,
    autocomplete: Optional[Callable] = None,
    path_type: str = "any",
    exists: Optional[bool] = None,
    normalize_to_absolute_path: bool = False,
    render: Optional[ConsoleRender] = None,
    raise_keyboard_interrupt: bool = False,
) -> str:
    render = render or ConsoleRender(raise_keyboard_interrupt=raise_keyboard_interrupt)
    question = questions.Path(
        name="",
        message=message,
        default=default,
        ignore=ignore,
        validate=validate,
        show_default=show_default,
        trim_header=trim_header,
        autocomplete=autocomplete,
        path_type=path_type,
        exists=exists,
        normalize_to_absolute_path=normalize_to_absolute_path,
    )
    return render.render(question)
