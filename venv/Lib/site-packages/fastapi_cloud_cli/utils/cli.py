import contextlib
import logging
from typing import Any, Dict, Generator, List, Optional, Tuple

import typer
from httpx import HTTPError, HTTPStatusError, ReadTimeout
from rich.segment import Segment
from rich_toolkit import RichToolkit, RichToolkitTheme
from rich_toolkit.progress import Progress
from rich_toolkit.styles import MinimalStyle, TaggedStyle

logger = logging.getLogger(__name__)


class FastAPIStyle(TaggedStyle):
    def __init__(self, tag_width: int = 11):
        super().__init__(tag_width=tag_width)

    def _get_tag_segments(
        self,
        metadata: Dict[str, Any],
        is_animated: bool = False,
        done: bool = False,
    ) -> Tuple[List[Segment], int]:
        if not is_animated:
            return super()._get_tag_segments(metadata, is_animated, done)

        emojis = [
            "🥚",
            "🐣",
            "🐤",
            "🐥",
            "🐓",
            "🐔",
        ]

        tag = emojis[self.animation_counter % len(emojis)]

        if done:
            tag = emojis[-1]

        left_padding = self.tag_width - 1
        left_padding = max(0, left_padding)

        return [Segment(tag)], left_padding


def get_rich_toolkit(minimal: bool = False) -> RichToolkit:
    style = MinimalStyle() if minimal else FastAPIStyle(tag_width=11)

    theme = RichToolkitTheme(
        style=style,
        theme={
            "tag.title": "white on #009485",
            "tag": "white on #007166",
            "placeholder": "grey85",
            "text": "white",
            "selected": "#007166",
            "result": "grey85",
            "progress": "on #007166",
            "error": "red",
        },
    )

    return RichToolkit(theme=theme)


@contextlib.contextmanager
def handle_http_errors(
    progress: Progress,
    message: Optional[str] = None,
) -> Generator[None, None, None]:
    try:
        yield
    except ReadTimeout as e:
        logger.debug(e)

        progress.set_error(
            "The request to the FastAPI Cloud server timed out. Please try again later."
        )

        raise typer.Exit(1) from None
    except HTTPError as e:
        logger.debug(e)

        # Handle validation errors from Pydantic models, this should make it easier to debug :)
        if isinstance(e, HTTPStatusError) and e.response.status_code == 422:
            logger.debug(e.response.json())  # pragma: no cover

        if isinstance(e, HTTPStatusError) and e.response.status_code in (401, 403):
            message = "The specified token is not valid. Use `fastapi login` to generate a new token."

        else:
            message = (
                message
                or f"Something went wrong while contacting the FastAPI Cloud server. Please try again later. \n\n{e}"
            )

        progress.set_error(message)

        raise typer.Exit(1) from None
