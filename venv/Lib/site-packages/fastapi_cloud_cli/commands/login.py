import logging
import time
from typing import Any

import httpx
import typer
from pydantic import BaseModel

from fastapi_cloud_cli.config import Settings
from fastapi_cloud_cli.utils.api import APIClient
from fastapi_cloud_cli.utils.auth import AuthConfig, write_auth_config
from fastapi_cloud_cli.utils.cli import get_rich_toolkit, handle_http_errors

logger = logging.getLogger(__name__)


class AuthorizationData(BaseModel):
    user_code: str
    device_code: str
    verification_uri: str
    verification_uri_complete: str
    interval: int = 5


class TokenResponse(BaseModel):
    access_token: str


def _start_device_authorization(
    client: httpx.Client,
) -> AuthorizationData:
    settings = Settings.get()

    response = client.post(
        "/login/device/authorization", data={"client_id": settings.client_id}
    )

    response.raise_for_status()

    return AuthorizationData.model_validate(response.json())


def _fetch_access_token(client: httpx.Client, device_code: str, interval: int) -> str:
    settings = Settings.get()

    while True:
        response = client.post(
            "/login/device/token",
            data={
                "device_code": device_code,
                "client_id": settings.client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )

        if response.status_code not in (200, 400):
            response.raise_for_status()

        if response.status_code == 400:
            data = response.json()

            if data.get("error") != "authorization_pending":
                response.raise_for_status()

        if response.status_code == 200:
            break

        time.sleep(interval)

    response_data = TokenResponse.model_validate(response.json())

    return response_data.access_token


def login() -> Any:
    """
    Login to FastAPI Cloud. 🚀
    """
    with get_rich_toolkit() as toolkit, APIClient() as client:
        toolkit.print_title("Login to FastAPI Cloud", tag="FastAPI")

        toolkit.print_line()

        with toolkit.progress("Starting authorization") as progress:
            with handle_http_errors(progress):
                authorization_data = _start_device_authorization(client)

            url = authorization_data.verification_uri_complete

            progress.log(f"Opening [link={url}]{url}[/link]")

        toolkit.print_line()

        with toolkit.progress("Waiting for user to authorize...") as progress:
            typer.launch(url)

            with handle_http_errors(progress):
                access_token = _fetch_access_token(
                    client, authorization_data.device_code, authorization_data.interval
                )

            write_auth_config(AuthConfig(access_token=access_token))

            progress.log("Now you are logged in! 🚀")
