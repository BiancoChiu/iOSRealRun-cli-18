import json
from pathlib import Path

from pydantic import BaseModel

from .utils.config import get_cli_config_path


class Settings(BaseModel):
    base_api_url: str = "https://api.fastapicloud.com/api/v1"
    client_id: str = "fastapi-cli"

    @classmethod
    def from_user_settings(cls, config_path: Path) -> "Settings":
        try:
            content = config_path.read_bytes() if config_path.exists() else b"{}"

            user_settings = json.loads(content)
        except json.JSONDecodeError:
            user_settings = {}

        return cls(**user_settings)

    @classmethod
    def get(cls) -> "Settings":
        return cls.from_user_settings(get_cli_config_path())
