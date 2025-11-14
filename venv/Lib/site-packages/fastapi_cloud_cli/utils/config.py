from pathlib import Path

import typer


def get_config_folder() -> Path:
    return Path(typer.get_app_dir("fastapi-cli"))


def get_auth_path() -> Path:
    auth_path = get_config_folder() / "auth.json"
    auth_path.parent.mkdir(parents=True, exist_ok=True)

    return auth_path


def get_cli_config_path() -> Path:
    cli_config_path = get_config_folder() / "cli.json"
    cli_config_path.parent.mkdir(parents=True, exist_ok=True)

    return cli_config_path
