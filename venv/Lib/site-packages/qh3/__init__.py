from __future__ import annotations

import logging

from .asyncio import QuicConnectionProtocol, connect, serve
from .h3 import events as h3_events
from .h3.connection import H3Connection, ProtocolError
from .h3.exceptions import H3Error, NoAvailablePushIDError
from .quic import events as quic_events
from .quic.configuration import QuicConfiguration
from .quic.connection import QuicConnection, QuicConnectionError
from .quic.logger import QuicFileLogger, QuicLogger
from .quic.packet import QuicProtocolVersion
from .tls import CipherSuite, SessionTicket

__version__ = "1.5.6"

__all__ = (
    "connect",
    "QuicConnectionProtocol",
    "serve",
    "h3_events",
    "H3Error",
    "H3Connection",
    "NoAvailablePushIDError",
    "quic_events",
    "QuicConfiguration",
    "QuicConnection",
    "QuicConnectionError",
    "QuicProtocolVersion",
    "QuicFileLogger",
    "QuicLogger",
    "ProtocolError",
    "CipherSuite",
    "SessionTicket",
    "__version__",
)

# Attach a NullHandler to the top level logger by default
# https://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
logging.getLogger("quic").addHandler(logging.NullHandler())
logging.getLogger("http3").addHandler(logging.NullHandler())
