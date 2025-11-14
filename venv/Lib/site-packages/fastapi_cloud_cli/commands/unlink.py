import logging
import shutil
from pathlib import Path
from typing import Any

import typer

from fastapi_cloud_cli.utils.cli import get_rich_toolkit

logger = logging.getLogger(__name__)


def unlink() -> Any:
    """
    Unlink by deleting the `.fastapicloud` directory.
    """
    with get_rich_toolkit(minimal=True) as toolkit:
        config_dir = Path.cwd() / ".fastapicloud"

        if not config_dir.exists():
            toolkit.print(
                "No FastAPI Cloud configuration found in the current directory."
            )
            logger.debug(f"Configuration directory not found: {config_dir}")
            raise typer.Exit(1)

        shutil.rmtree(config_dir)
        toolkit.print("FastAPI Cloud configuration has been unlinked successfully! 🚀")
        logger.debug(f"Deleted configuration directory: {config_dir}")
