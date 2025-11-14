import typer

from .commands.deploy import deploy
from .commands.env import env_app
from .commands.login import login
from .commands.logout import logout
from .commands.unlink import unlink
from .commands.whoami import whoami
from .logging import setup_logging
from .utils.sentry import init_sentry

setup_logging()

app = typer.Typer(rich_markup_mode="rich")


# TODO: use the app structure

# Additional commands
app.command()(deploy)
app.command()(login)
app.command()(logout)
app.command()(whoami)
app.command()(unlink)

app.add_typer(env_app, name="env")


def main() -> None:
    init_sentry()
    app()
