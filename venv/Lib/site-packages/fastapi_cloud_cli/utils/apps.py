import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger("fastapi_cli")


class AppConfig(BaseModel):
    app_id: str
    team_id: str


def get_app_config(path_to_deploy: Path) -> Optional[AppConfig]:
    config_path = path_to_deploy / ".fastapicloud/cloud.json"
    logger.debug("Looking for app config at: %s", config_path)

    if not config_path.exists():
        logger.debug("App config file doesn't exist")
        return None

    logger.debug("App config loaded successfully")
    return AppConfig.model_validate_json(config_path.read_text(encoding="utf-8"))


README = """
> Why do I have a folder named ".fastapicloud" in my project? 🤔
The ".fastapicloud" folder is created when you link a directory to a FastAPI Cloud project.

> What does the "cloud.json" file contain?
The "cloud.json" file contains:
- The ID of the FastAPI app that you linked ("app_id")
- The ID of the team your FastAPI Cloud project is owned by ("team_id")

> Should I commit the ".fastapicloud" folder?
No, you should not commit the ".fastapicloud" folder to your version control system.
That's why there's a ".gitignore" file in this folder.
"""


def write_app_config(path_to_deploy: Path, app_config: AppConfig) -> None:
    config_path = path_to_deploy / ".fastapicloud/cloud.json"
    readme_path = path_to_deploy / ".fastapicloud/README.md"
    gitignore_path = path_to_deploy / ".fastapicloud/.gitignore"

    logger.debug("Writing app config to: %s", config_path)
    logger.debug("App config data: %s", app_config)

    config_path.parent.mkdir(parents=True, exist_ok=True)

    config_path.write_text(
        app_config.model_dump_json(),
        encoding="utf-8",
    )
    readme_path.write_text(README, encoding="utf-8")
    gitignore_path.write_text("*")

    logger.debug("App config files written successfully")
