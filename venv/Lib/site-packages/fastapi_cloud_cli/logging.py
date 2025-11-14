import logging
import os
from typing import Union

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(
    terminal_width: Union[int, None] = None, level: Union[int, None] = None
) -> None:
    if level is None:
        level = (
            logging.DEBUG if os.getenv("FASTAPI_CLOUD_DEBUG") == "1" else logging.INFO
        )

    logger = logging.getLogger("fastapi_cloud_cli")
    console = Console(width=terminal_width) if terminal_width else None
    rich_handler = RichHandler(
        show_time=False,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        markup=True,
        show_path=False,
        console=console,
    )
    rich_handler.setFormatter(logging.Formatter("{message}", style="{"))
    logger.addHandler(rich_handler)

    logger.setLevel(level)
    logger.propagate = False
