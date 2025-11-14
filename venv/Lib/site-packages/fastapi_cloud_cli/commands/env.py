import logging
from pathlib import Path
from typing import Any, List, Union

import typer
from pydantic import BaseModel
from typing_extensions import Annotated

from fastapi_cloud_cli.utils.api import APIClient
from fastapi_cloud_cli.utils.apps import get_app_config
from fastapi_cloud_cli.utils.auth import is_logged_in
from fastapi_cloud_cli.utils.cli import get_rich_toolkit, handle_http_errors
from fastapi_cloud_cli.utils.env import validate_environment_variable_name

logger = logging.getLogger(__name__)


class EnvironmentVariable(BaseModel):
    name: str
    value: str


class EnvironmentVariableResponse(BaseModel):
    data: List[EnvironmentVariable]


def _get_environment_variables(app_id: str) -> EnvironmentVariableResponse:
    with APIClient() as client:
        response = client.get(f"/apps/{app_id}/environment-variables/")
        response.raise_for_status()

        return EnvironmentVariableResponse.model_validate(response.json())


def _delete_environment_variable(app_id: str, name: str) -> bool:
    with APIClient() as client:
        response = client.delete(f"/apps/{app_id}/environment-variables/{name}")

    if response.status_code == 404:
        return False

    response.raise_for_status()

    return True


def _set_environment_variable(
    app_id: str, name: str, value: str, is_secret: bool = False
) -> None:
    with APIClient() as client:
        response = client.post(
            f"/apps/{app_id}/environment-variables/",
            json={"name": name, "value": value, "is_secret": is_secret},
        )
        response.raise_for_status()


env_app = typer.Typer()


@env_app.command()
def list(
    path: Annotated[
        Union[Path, None],
        typer.Argument(
            help="A path to the folder containing the app you want to deploy"
        ),
    ] = None,
) -> Any:
    """
    List the environment variables for the app.
    """

    with get_rich_toolkit(minimal=True) as toolkit:
        if not is_logged_in():
            toolkit.print(
                "No credentials found. Use [blue]`fastapi login`[/] to login.",
                tag="auth",
            )

            raise typer.Exit(1)

        app_path = path or Path.cwd()

        app_config = get_app_config(app_path)

        if not app_config:
            toolkit.print(
                f"No app found in the folder [bold]{app_path}[/].",
            )
            raise typer.Exit(1)

        with toolkit.progress(
            "Fetching environment variables...", transient=True
        ) as progress:
            with handle_http_errors(progress):
                environment_variables = _get_environment_variables(app_config.app_id)

        if not environment_variables.data:
            toolkit.print("No environment variables found.")
            return

        toolkit.print("Environment variables:")
        toolkit.print_line()

        for env_var in environment_variables.data:
            toolkit.print(f"[bold]{env_var.name}[/]")


@env_app.command()
def delete(
    name: Union[str, None] = typer.Argument(
        None,
        help="The name of the environment variable to delete",
    ),
    path: Annotated[
        Union[Path, None],
        typer.Argument(
            help="A path to the folder containing the app you want to deploy"
        ),
    ] = None,
) -> Any:
    """
    Delete an environment variable from the app.
    """

    with get_rich_toolkit(minimal=True) as toolkit:
        # TODO: maybe this logic can be extracted to a function
        if not is_logged_in():
            toolkit.print(
                "No credentials found. Use [blue]`fastapi login`[/] to login.",
                tag="auth",
            )

            raise typer.Exit(1)

        path_to_deploy = path or Path.cwd()

        app_config = get_app_config(path_to_deploy)

        if not app_config:
            toolkit.print(
                f"No app found in the folder [bold]{path_to_deploy}[/].",
            )
            raise typer.Exit(1)

        if not name:
            with toolkit.progress(
                "Fetching environment variables...", transient=True
            ) as progress:
                with handle_http_errors(progress):
                    environment_variables = _get_environment_variables(
                        app_config.app_id
                    )

            if not environment_variables.data:
                toolkit.print("No environment variables found.")
                return

            name = toolkit.ask(
                "Select the environment variable to delete:",
                options=[
                    {"name": env_var.name, "value": env_var.name}
                    for env_var in environment_variables.data
                ],
            )

            assert name
        else:
            if not validate_environment_variable_name(name):
                toolkit.print(
                    f"The environment variable name [bold]{name}[/] is invalid."
                )
                raise typer.Exit(1)

            toolkit.print_line()

        with toolkit.progress(
            "Deleting environment variable", transient=True
        ) as progress:
            with handle_http_errors(progress):
                deleted = _delete_environment_variable(app_config.app_id, name)

        if not deleted:
            toolkit.print("Environment variable not found.")
            raise typer.Exit(1)

        toolkit.print(f"Environment variable [bold]{name}[/] deleted.")


@env_app.command()
def set(
    name: Union[str, None] = typer.Argument(
        None,
        help="The name of the environment variable to set",
    ),
    value: Union[str, None] = typer.Argument(
        None,
        help="The value of the environment variable to set",
    ),
    path: Annotated[
        Union[Path, None],
        typer.Argument(
            help="A path to the folder containing the app you want to deploy"
        ),
    ] = None,
) -> Any:
    """
    Set an environment variable for the app.
    """

    with get_rich_toolkit(minimal=True) as toolkit:
        if not is_logged_in():
            toolkit.print(
                "No credentials found. Use [blue]`fastapi login`[/] to login.",
                tag="auth",
            )

            raise typer.Exit(1)

        path_to_deploy = path or Path.cwd()

        app_config = get_app_config(path_to_deploy)

        if not app_config:
            toolkit.print(
                f"No app found in the folder [bold]{path_to_deploy}[/].",
            )
            raise typer.Exit(1)

        if not name:
            name = toolkit.input("Enter the name of the environment variable to set:")

        if not value:
            value = toolkit.input(
                "Enter the value of the environment variable to set:", password=True
            )

        with toolkit.progress(
            "Setting environment variable", transient=True
        ) as progress:
            assert name is not None
            assert value is not None

            with handle_http_errors(progress):
                _set_environment_variable(app_config.app_id, name, value)

        toolkit.print(f"Environment variable [bold]{name}[/] set.")
