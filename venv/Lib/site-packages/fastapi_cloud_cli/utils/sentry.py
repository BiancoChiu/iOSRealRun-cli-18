import sentry_sdk
from sentry_sdk.integrations.typer import TyperIntegration

from .auth import is_logged_in

SENTRY_DSN = "https://230250605ea4b58a0b69c768e9ec1168@o4506985151856640.ingest.us.sentry.io/4508449198899200"


def init_sentry() -> None:
    """Initialize Sentry error tracking only if user is logged in."""
    if not is_logged_in():
        return

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[TyperIntegration()],
        send_default_pii=False,
    )
