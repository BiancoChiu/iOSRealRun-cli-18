import logging
from typing import Any

from rich import print
from rich_toolkit.progress import Progress

from fastapi_cloud_cli.utils.api import APIClient
from fastapi_cloud_cli.utils.auth import is_logged_in
from fastapi_cloud_cli.utils.cli import handle_http_errors

logger = logging.getLogger(__name__)


def whoami() -> Any:
    if not is_logged_in():
        print("No credentials found. Use [blue]`fastapi login`[/] to login.")
        return

    with APIClient() as client:
        with Progress(title="⚡ Fetching profile", transient=True) as progress:
            with handle_http_errors(progress, message=""):
                response = client.get("/users/me")
                response.raise_for_status()

        data = response.json()

        print(f"⚡ [bold]{data['email']}[/bold]")
