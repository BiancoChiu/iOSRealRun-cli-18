import httpx

from fastapi_cloud_cli import __version__
from fastapi_cloud_cli.config import Settings
from fastapi_cloud_cli.utils.auth import get_auth_token


class APIClient(httpx.Client):
    def __init__(self) -> None:
        settings = Settings.get()

        token = get_auth_token()

        super().__init__(
            base_url=settings.base_api_url,
            timeout=httpx.Timeout(20),
            headers={
                "Authorization": f"Bearer {token}",
                "User-Agent": f"fastapi-cloud-cli/{__version__}",
            },
        )
