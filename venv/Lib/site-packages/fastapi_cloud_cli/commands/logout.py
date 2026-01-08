from fastapi_cloud_cli.utils.auth import delete_auth_config
from fastapi_cloud_cli.utils.cli import get_rich_toolkit


def logout() -> None:
    """
    Logout from FastAPI Cloud. 🚀
    """
    with get_rich_toolkit(minimal=True) as toolkit:
        delete_auth_config()

        toolkit.print("You are now logged out! 🚀")
