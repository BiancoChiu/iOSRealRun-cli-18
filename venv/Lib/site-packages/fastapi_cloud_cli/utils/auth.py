import logging
from typing import Optional

from pydantic import BaseModel

from .config import get_auth_path

logger = logging.getLogger("fastapi_cli")


class AuthConfig(BaseModel):
    access_token: str


def write_auth_config(auth_data: AuthConfig) -> None:
    auth_path = get_auth_path()
    logger.debug("Writing auth config to: %s", auth_path)

    auth_path.write_text(auth_data.model_dump_json(), encoding="utf-8")
    logger.debug("Auth config written successfully")


def delete_auth_config() -> None:
    auth_path = get_auth_path()
    logger.debug("Deleting auth config at: %s", auth_path)

    if auth_path.exists():
        auth_path.unlink()
        logger.debug("Auth config deleted successfully")
    else:
        logger.debug("Auth config file doesn't exist, nothing to delete")


def read_auth_config() -> Optional[AuthConfig]:
    auth_path = get_auth_path()
    logger.debug("Reading auth config from: %s", auth_path)

    if not auth_path.exists():
        logger.debug("Auth config file doesn't exist")
        return None

    logger.debug("Auth config loaded successfully")
    return AuthConfig.model_validate_json(auth_path.read_text(encoding="utf-8"))


def get_auth_token() -> Optional[str]:
    logger.debug("Getting auth token")
    auth_data = read_auth_config()

    if auth_data is None:
        logger.debug("No auth data found")
        return None

    logger.debug("Auth token retrieved successfully")
    return auth_data.access_token


def is_logged_in() -> bool:
    result = get_auth_token() is not None
    logger.debug("Login status: %s", result)
    return result
