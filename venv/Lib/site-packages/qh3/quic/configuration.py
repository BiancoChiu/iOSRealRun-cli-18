from __future__ import annotations

from dataclasses import dataclass, field
from os import PathLike
from re import split
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from .._hazmat import Certificate as X509Certificate
    from .._hazmat import DsaPrivateKey, EcPrivateKey, Ed25519PrivateKey, RsaPrivateKey

from ..tls import (
    CipherSuite,
    SessionTicket,
    load_pem_private_key,
    load_pem_x509_certificates,
)
from .logger import QuicLogger
from .packet import QuicProtocolVersion


@dataclass
class QuicConfiguration:
    """
    A QUIC configuration.
    """

    alpn_protocols: list[str] | None = None
    """
    A list of supported ALPN protocols.
    """

    connection_id_length: int = 8
    """
    The length in bytes of local connection IDs.
    """

    idle_timeout: float = 60.0
    """
    The idle timeout in seconds.

    The connection is terminated if nothing is received for the given duration.
    """

    is_client: bool = True
    """
    Whether this is the client side of the QUIC connection.
    """

    max_data: int = 1048576
    """
    Connection-wide flow control limit.
    """

    max_stream_data: int = 1048576
    """
    Per-stream flow control limit.
    """

    quic_logger: QuicLogger | None = None
    """
    The :class:`~qh3.quic.logger.QuicLogger` instance to log events to.
    """

    secrets_log_file: TextIO = None
    """
    A file-like object in which to log traffic secrets.

    This is useful to analyze traffic captures with Wireshark.
    """

    server_name: str | None = None
    """
    The server name to send during the TLS handshake the Server Name Indication.

    .. note:: This is only used by clients.
    """

    session_ticket: SessionTicket | None = None
    """
    The TLS session ticket which should be used for session resumption.
    """

    hostname_checks_common_name: bool = False
    assert_fingerprint: str | None = None
    verify_hostname: bool = True

    cadata: bytes | None = None
    cafile: str | None = None
    capath: str | None = None

    certificate: X509Certificate | None = None
    certificate_chain: list[X509Certificate] = field(default_factory=list)

    cipher_suites: list[CipherSuite] | None = None
    initial_rtt: float = 0.1

    max_datagram_frame_size: int | None = None
    original_version: int | None = None

    private_key: (
        EcPrivateKey | Ed25519PrivateKey | DsaPrivateKey | RsaPrivateKey | None
    ) = None

    quantum_readiness_test: bool = False
    supported_versions: list[int] = field(
        default_factory=lambda: [
            QuicProtocolVersion.VERSION_1,
            QuicProtocolVersion.VERSION_2,
        ]
    )
    verify_mode: int | None = None

    def load_cert_chain(
        self,
        certfile: str | bytes | PathLike,
        keyfile: str | bytes | PathLike | None = None,
        password: bytes | str | None = None,
    ) -> None:
        """
        Load a private key and the corresponding certificate.
        """

        if isinstance(certfile, str):
            certfile = certfile.encode()
        elif isinstance(certfile, PathLike):
            certfile = str(certfile).encode()

        if keyfile is not None:
            if isinstance(keyfile, str):
                keyfile = keyfile.encode()
            elif isinstance(keyfile, PathLike):
                keyfile = str(keyfile).encode()

        # we either have the certificate or a file path in certfile/keyfile.
        if b"-----BEGIN" not in certfile:
            with open(certfile, "rb") as fp:
                certfile = fp.read()
            if keyfile is not None:
                with open(keyfile, "rb") as fp:
                    keyfile = fp.read()

        is_crlf = b"-----\r\n" in certfile
        boundary = (
            b"-----BEGIN PRIVATE KEY-----\n"
            if not is_crlf
            else b"-----BEGIN PRIVATE KEY-----\r\n"
        )
        chunks = split(b"\n" + boundary, certfile)

        certificates = load_pem_x509_certificates(chunks[0])

        if len(chunks) == 2:
            private_key = boundary + chunks[1]
            self.private_key = load_pem_private_key(private_key)

        self.certificate = certificates[0]
        self.certificate_chain = certificates[1:]

        if keyfile is not None:
            self.private_key = load_pem_private_key(
                keyfile,
                password=(
                    password.encode("utf8") if isinstance(password, str) else password
                ),
            )

    def load_verify_locations(
        self,
        cafile: str | None = None,
        capath: str | None = None,
        cadata: bytes | None = None,
    ) -> None:
        """
        Load a set of "certification authority" (CA) certificates used to
        validate other peers' certificates.
        """
        self.cafile = cafile
        self.capath = capath
        self.cadata = cadata
