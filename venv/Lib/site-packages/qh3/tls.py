from __future__ import annotations

import datetime
import glob
import hashlib
import logging
import os
import re
import ssl
import struct
from binascii import unhexlify
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from functools import lru_cache, partial
from hmac import HMAC
from typing import Any, Callable, Generator, Optional, Sequence, Tuple, TypeVar

from ._hazmat import (
    Buffer,
    BufferReadError,
    CryptoError,
    DsaPrivateKey,
    ECDHP256KeyExchange,
    ECDHP384KeyExchange,
    ECDHP521KeyExchange,
    EcPrivateKey,
    Ed25519PrivateKey,
    ExpiredCertificateError,
    InvalidNameCertificateError,
    KeyType,
    PrivateKeyInfo,
    RsaPrivateKey,
    SelfSignedCertificateError,
    ServerVerifier,
    SignatureError,
    TlsCertUsage,
    UnacceptableCertificateError,
    X25519KeyExchange,
    X25519ML768KeyExchange,
    idna_encode,
    rebuild_chain,
    verify_with_public_key,
)
from ._hazmat import (
    Certificate as X509Certificate,
)

_HASHED_CERT_FILENAME_RE = re.compile(r"^[0-9a-fA-F]{8}\.[0-9]$")

TLS_VERSION_GREASE = 0x0A0A
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304

T = TypeVar("T")

# Maps the length of a digest to a possible hash function producing this digest
HASHFUNC_MAP = {
    length: getattr(hashlib, algorithm, None)
    for length, algorithm in (
        (32, "md5"),  # some algorithm may be unavailable
        (40, "sha1"),
        (64, "sha256"),
    )
}


# facilitate mocking for the test suite
def utcnow(remove_tz: bool = True) -> datetime.datetime:
    dt = datetime.datetime.now(datetime.timezone.utc)
    return dt.replace(tzinfo=None) if remove_tz else dt


class AlertDescription(IntEnum):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


class Alert(Exception):
    description: AlertDescription


class AlertBadCertificate(Alert):
    description = AlertDescription.bad_certificate


class AlertCertificateExpired(Alert):
    description = AlertDescription.certificate_expired


class AlertDecryptError(Alert):
    description = AlertDescription.decrypt_error


class AlertHandshakeFailure(Alert):
    description = AlertDescription.handshake_failure


class AlertIllegalParameter(Alert):
    description = AlertDescription.illegal_parameter


class AlertInternalError(Alert):
    description = AlertDescription.internal_error


class AlertProtocolVersion(Alert):
    description = AlertDescription.protocol_version


class AlertUnexpectedMessage(Alert):
    description = AlertDescription.unexpected_message


class Direction(IntEnum):
    DECRYPT = 0
    ENCRYPT = 1


class Epoch(IntEnum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    ONE_RTT = 3


class State(IntEnum):
    CLIENT_HANDSHAKE_START = 0
    CLIENT_EXPECT_SERVER_HELLO = 1
    CLIENT_EXPECT_ENCRYPTED_EXTENSIONS = 2
    CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE = 3
    CLIENT_EXPECT_CERTIFICATE_CERTIFICATE = 4
    CLIENT_EXPECT_CERTIFICATE_VERIFY = 5
    CLIENT_EXPECT_FINISHED = 6
    CLIENT_POST_HANDSHAKE = 7

    SERVER_EXPECT_CLIENT_HELLO = 8
    SERVER_EXPECT_FINISHED = 9
    SERVER_POST_HANDSHAKE = 10


class HKDFExpand:
    def __init__(
        self,
        algorithm: int,
        length: int,
        info: bytes | None,
    ):
        self._algorithm = algorithm
        self._digest_size = int(algorithm / 8)

        max_length = 255 * self._digest_size

        if length > max_length:
            raise ValueError(f"Cannot derive keys larger than {max_length} octets.")

        self._length = length

        if info is None:
            info = b""

        self._info = info
        self._used = False

    def _expand(self, key_material: bytes) -> bytes:
        output = [b""]
        counter = 1

        while self._digest_size * (len(output) - 1) < self._length:
            h = HMAC(key_material, digestmod=f"sha{self._algorithm}")
            h.update(output[-1])
            h.update(self._info)
            h.update(bytes([counter]))
            output.append(h.digest())
            counter += 1

        return b"".join(output)[: self._length]

    def derive(self, key_material: bytes) -> bytes:
        if self._used:
            raise CryptoError

        self._used = True
        return self._expand(key_material)


def hkdf_label(label: bytes, hash_value: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    return (
        struct.pack("!HB", length, len(full_label))
        + full_label
        + struct.pack("!B", len(hash_value))
        + hash_value
    )


def hkdf_expand_label(
    algorithm: int,
    secret: bytes,
    label: bytes,
    hash_value: bytes,
    length: int,
) -> bytes:
    return HKDFExpand(
        algorithm=algorithm,
        length=length,
        info=hkdf_label(label, hash_value, length),
    ).derive(secret)


def hkdf_extract(algorithm: int, salt: bytes, key_material: bytes) -> bytes:
    h = HMAC(salt, digestmod=f"sha{algorithm}")
    h.update(key_material)
    return h.digest()


def load_pem_private_key(
    data: bytes, password: bytes | None = None
) -> EcPrivateKey | DsaPrivateKey | RsaPrivateKey | Ed25519PrivateKey:
    """
    Load a PEM-encoded private key.
    """
    pkey_info = PrivateKeyInfo(data, password)

    if pkey_info.get_type() in [
        KeyType.ECDSA_P256,
        KeyType.ECDSA_P384,
        KeyType.ECDSA_P521,
    ]:
        curve_type = None
        if pkey_info.get_type() == KeyType.ECDSA_P256:
            curve_type = 256
        elif pkey_info.get_type() == KeyType.ECDSA_P384:
            curve_type = 384
        elif pkey_info.get_type() == KeyType.ECDSA_P521:
            curve_type = 521

        assert curve_type is not None

        return EcPrivateKey(
            pkey_info.public_bytes(), curve_type, b"BEGIN EC PRIVATE KEY" not in data
        )
    elif pkey_info.get_type() == KeyType.DSA:
        return DsaPrivateKey(pkey_info.public_bytes())
    elif pkey_info.get_type() == KeyType.RSA:
        return RsaPrivateKey(pkey_info.public_bytes())
    elif pkey_info.get_type() == KeyType.ED25519:
        return Ed25519PrivateKey(pkey_info.public_bytes())

    raise ssl.SSLError("Unsupported private key format")


def load_pem_x509_certificates(data: bytes) -> list[X509Certificate]:
    """
    Load a chain of PEM-encoded X509 certificates.
    """
    line_ending = b"\n" if b"-----\r\n" not in data else b"\r\n"
    boundary = b"-----END CERTIFICATE-----" + line_ending
    certificates = []
    for chunk in data.split(boundary):
        if chunk:
            start_marker = chunk.find(b"-----BEGIN CERTIFICATE-----" + line_ending)
            if start_marker == -1:
                break
            pem_reconstructed = b"".join([chunk[start_marker:], boundary]).decode(
                "ascii"
            )
            certificates.append(
                X509Certificate(ssl.PEM_cert_to_DER_cert(pem_reconstructed))
            )
    return certificates


def _capath_contains_certs(capath: str) -> bool:
    """Check whether capath exists and contains certs in the expected format."""
    if not os.path.isdir(capath):
        return False
    for name in os.listdir(capath):
        if _HASHED_CERT_FILENAME_RE.match(name):
            return True
    return False


@lru_cache(maxsize=64)
def load_store_and_sort(
    cadata: bytes | None = None,
    cafile: str | None = None,
    capath: str | None = None,
) -> tuple[list[X509Certificate], list[X509Certificate], list[X509Certificate]]:
    """
    Given cadata, cafile and capath load X509 certificates and sort
    them into three distinct list:
        - Trust anchors (ca self-signed)
        - Intermediates (ca signed by other ca)
        - Others (not suitable for our purposes)

    This function consumes a lot of CPU times, so we want to cache it.
    """
    trust_anchors = []
    intermediaries = []
    others = []

    def _sort_cert_in_appropriate_list(c) -> None:
        nonlocal trust_anchors, intermediaries, others

        if c.self_signed:
            # root CA must be tagged OTHER
            # EKU must not have client auth
            # or server auth. it's a red flag! period.
            if c.usage != TlsCertUsage.Other:
                others.append(c)
            else:
                trust_anchors.append(c)
        else:
            intermediaries.append(c)

    if cadata is not None:
        for cert in load_pem_x509_certificates(cadata):
            _sort_cert_in_appropriate_list(cert)

    if cafile is not None or capath is not None:
        if cafile:
            with open(cafile, "rb") as fp:
                for cert in load_pem_x509_certificates(fp.read()):
                    _sort_cert_in_appropriate_list(cert)
        if capath and _capath_contains_certs(capath):
            for path in glob.glob(f"{capath}/*"):
                with open(path, "rb") as fp:
                    for cert in load_pem_x509_certificates(fp.read()):
                        _sort_cert_in_appropriate_list(cert)

    if cadata is None and cafile is None and capath is None:
        default_ctx = ssl.create_default_context()
        default_ctx.load_default_certs()

        for ca in default_ctx.get_ca_certs(binary_form=True):
            _sort_cert_in_appropriate_list(X509Certificate(ca))

    return trust_anchors, intermediaries, others


def verify_certificate(
    certificate: X509Certificate,
    chain: list[X509Certificate] = None,
    cadata: bytes | None = None,
    cafile: str | None = None,
    capath: str | None = None,
    server_name: str | None = None,
    assert_server_name: bool = True,
    ocsp_response: bytes | None = None,
) -> None:
    if chain is None:
        chain = []

    trust_anchors, intermediaries, _ = load_store_and_sort(
        cadata=cadata,
        cafile=cafile,
        capath=capath,
    )

    if server_name is None or assert_server_name is False:
        # get_subject_alt_names()... caution for :
        # IPAddress(20:01:48:60:48:60:00:00:00:00:00:00:00:00:00:64)
        # or..
        # IPAddress(08:08:08:08)
        for alt_name in certificate.get_subject_alt_names():
            server_name_candidate = alt_name.decode()
            server_name_candidate = server_name_candidate[
                server_name_candidate.find("(") + 1 : server_name_candidate.find(")")
            ]
            server_name_candidate.replace("*.", "unverified.")

            if ":" in server_name_candidate:
                if len(server_name_candidate) == 11:
                    server_name = ".".join(
                        str(int(p)) for p in server_name_candidate.split(":")
                    )
                else:
                    continue

            else:
                server_name = server_name_candidate

            break

    if server_name is None:
        raise AlertBadCertificate("unable to determine server name target")

    if not trust_anchors:
        raise AlertBadCertificate(
            "unable to get local issuer certificate (empty CA store)"
        )

    # rebuild the intermediate chain locally
    # in case the server did not pass them along
    # and the configuration does hold a list of intermediates.
    if not chain and intermediaries:
        raw_chain = rebuild_chain(
            certificate.public_bytes(),
            [c.public_bytes() for c in intermediaries],
        )

        if len(raw_chain) >= 2:
            for i in raw_chain[1:]:
                chain.append(X509Certificate(i))
        else:
            chain = []

    # load CAs
    try:
        store = ServerVerifier([c.public_bytes() for c in trust_anchors])
    except CryptoError as e:
        raise AlertBadCertificate("unable to create the verifier x509 store") from e

    try:
        store.verify(
            certificate.public_bytes(),
            [c.public_bytes() for c in chain],
            server_name,
            ocsp_response or b"",
        )
    except (
        SelfSignedCertificateError,
        InvalidNameCertificateError,
        ExpiredCertificateError,
        UnacceptableCertificateError,
    ) as exc:
        if isinstance(exc, InvalidNameCertificateError) and assert_server_name is False:
            return
        raise AlertBadCertificate(exc.args[0])


class CipherSuite(IntEnum):
    AES_128_GCM_SHA256 = 0x1301
    AES_256_GCM_SHA384 = 0x1302
    CHACHA20_POLY1305_SHA256 = 0x1303
    EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
    GREASE = 0xDADA


class CompressionMethod(IntEnum):
    NULL = 0


class ExtensionType(IntEnum):
    SERVER_NAME = 0
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    ALPN = 16
    COMPRESS_CERTIFICATE = 27
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    KEY_SHARE = 51
    QUIC_TRANSPORT_PARAMETERS = 0x0039
    ENCRYPTED_SERVER_NAME = 65486
    GREASE = 0x0A0A


class Group(IntEnum):
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519KYBER768DRAFT00 = 0x6399
    X25519ML768 = 0x11EC
    X25519 = 0x001D
    X448 = 0x001E
    GREASE = 0xAAAA


class HandshakeType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    COMPRESSED_CERTIFICATE = 25
    MESSAGE_HASH = 254


class PskKeyExchangeMode(IntEnum):
    PSK_KE = 0
    PSK_DHE_KE = 1


class SignatureAlgorithm(IntEnum):
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603
    ED25519 = 0x0807
    ED448 = 0x0808  # unsupported
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806

    # unsafe, and unsupported (by us)!
    RSA_PKCS1_SHA1 = 0x0201
    SHA1_DSA = 0x0202
    ECDSA_SHA1 = 0x0203


# BLOCKS


@contextmanager
def pull_block(buf: Buffer, capacity: int) -> Generator:
    length = int.from_bytes(buf.pull_bytes(capacity), byteorder="big")
    end = buf.tell() + length
    yield length
    assert buf.tell() == end


@contextmanager
def push_block(buf: Buffer, capacity: int) -> Generator:
    """
    Context manager to push a variable-length block, with `capacity` bytes
    to write the length.
    """
    start = buf.tell() + capacity
    buf.seek(start)
    yield
    end = buf.tell()
    length = end - start
    buf.seek(start - capacity)
    buf.push_bytes(length.to_bytes(capacity, byteorder="big"))
    buf.seek(end)


# LISTS


def pull_list(buf: Buffer, capacity: int, func: Callable[[], T]) -> list[T]:
    """
    Pull a list of items.
    """
    items = []
    with pull_block(buf, capacity) as length:
        end = buf.tell() + length
        while buf.tell() < end:
            items.append(func())
    return items


def push_list(
    buf: Buffer, capacity: int, func: Callable[[T], None], values: Sequence[T]
) -> None:
    """
    Push a list of items.
    """
    with push_block(buf, capacity):
        for value in values:
            func(value)


def pull_opaque(buf: Buffer, capacity: int) -> bytes:
    """
    Pull an opaque value prefixed by a length.
    """
    with pull_block(buf, capacity) as length:
        return buf.pull_bytes(length)


def push_opaque(buf: Buffer, capacity: int, value: bytes) -> None:
    """
    Push an opaque value prefix by a length.
    """
    with push_block(buf, capacity):
        buf.push_bytes(value)


@contextmanager
def push_extension(buf: Buffer, extension_type: int) -> Generator:
    buf.push_uint16(extension_type)
    with push_block(buf, 2):
        yield


# KeyShareEntry


KeyShareEntry = Tuple[int, bytes]


def pull_key_share(buf: Buffer) -> KeyShareEntry:
    group = buf.pull_uint16()
    data = pull_opaque(buf, 2)
    return (group, data)


def push_key_share(buf: Buffer, value: KeyShareEntry) -> None:
    buf.push_uint16(value[0])
    push_opaque(buf, 2, value[1])


# ALPN


def pull_alpn_protocol(buf: Buffer) -> str:
    return pull_opaque(buf, 1).decode("ascii")


def push_alpn_protocol(buf: Buffer, protocol: str) -> None:
    push_opaque(buf, 1, protocol.encode("ascii"))


# PRE SHARED KEY

PskIdentity = Tuple[bytes, int]


def pull_psk_identity(buf: Buffer) -> PskIdentity:
    identity = pull_opaque(buf, 2)
    obfuscated_ticket_age = buf.pull_uint32()
    return (identity, obfuscated_ticket_age)


def push_psk_identity(buf: Buffer, entry: PskIdentity) -> None:
    push_opaque(buf, 2, entry[0])
    buf.push_uint32(entry[1])


def pull_psk_binder(buf: Buffer) -> bytes:
    return pull_opaque(buf, 1)


def push_psk_binder(buf: Buffer, binder: bytes) -> None:
    push_opaque(buf, 1, binder)


# MESSAGES

Extension = Tuple[int, bytes]


@dataclass
class OfferedPsks:
    identities: list[PskIdentity]
    binders: list[bytes]


@dataclass
class ClientHello:
    random: bytes
    legacy_session_id: bytes
    cipher_suites: list[int]
    legacy_compression_methods: list[int]

    # extensions
    alpn_protocols: list[str] | None = None
    early_data: bool = False
    key_share: list[KeyShareEntry] | None = None
    pre_shared_key: OfferedPsks | None = None
    psk_key_exchange_modes: list[int] | None = None
    server_name: str | None = None
    signature_algorithms: list[int] | None = None
    supported_groups: list[int] | None = None
    supported_versions: list[int] | None = None

    other_extensions: list[Extension] = field(default_factory=list)


def pull_client_hello(buf: Buffer) -> ClientHello:
    assert buf.pull_uint8() == HandshakeType.CLIENT_HELLO
    with pull_block(buf, 3):
        assert buf.pull_uint16() == TLS_VERSION_1_2

        hello = ClientHello(
            random=buf.pull_bytes(32),
            legacy_session_id=pull_opaque(buf, 1),
            cipher_suites=pull_list(buf, 2, buf.pull_uint16),
            legacy_compression_methods=pull_list(buf, 1, buf.pull_uint8),
        )

        # extensions
        after_psk = False

        def pull_extension() -> None:
            # pre_shared_key MUST be last
            nonlocal after_psk
            assert not after_psk

            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.KEY_SHARE:
                hello.key_share = pull_list(buf, 2, partial(pull_key_share, buf))
            elif extension_type == ExtensionType.SUPPORTED_VERSIONS:
                hello.supported_versions = pull_list(buf, 1, buf.pull_uint16)
            elif extension_type == ExtensionType.SIGNATURE_ALGORITHMS:
                hello.signature_algorithms = pull_list(buf, 2, buf.pull_uint16)
            elif extension_type == ExtensionType.SUPPORTED_GROUPS:
                hello.supported_groups = pull_list(buf, 2, buf.pull_uint16)
            elif extension_type == ExtensionType.PSK_KEY_EXCHANGE_MODES:
                hello.psk_key_exchange_modes = pull_list(buf, 1, buf.pull_uint8)
            elif extension_type == ExtensionType.SERVER_NAME:
                with pull_block(buf, 2):
                    assert buf.pull_uint8() == 0
                    hello.server_name = pull_opaque(buf, 2).decode("ascii")
            elif extension_type == ExtensionType.ALPN:
                hello.alpn_protocols = pull_list(
                    buf, 2, partial(pull_alpn_protocol, buf)
                )
            elif extension_type == ExtensionType.EARLY_DATA:
                hello.early_data = True
            elif extension_type == ExtensionType.PRE_SHARED_KEY:
                hello.pre_shared_key = OfferedPsks(
                    identities=pull_list(buf, 2, partial(pull_psk_identity, buf)),
                    binders=pull_list(buf, 2, partial(pull_psk_binder, buf)),
                )
                after_psk = True
            elif extension_type == ExtensionType.STATUS_REQUEST:
                buf.pull_bytes(
                    extension_length
                )  # we don't implement it for the server...
            elif extension_type == ExtensionType.GREASE:
                pass  # simply ignore it!
            else:
                hello.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return hello


def push_client_hello(buf: Buffer, hello: ClientHello) -> None:
    buf.push_uint8(HandshakeType.CLIENT_HELLO)
    with push_block(buf, 3):
        buf.push_uint16(TLS_VERSION_1_2)
        buf.push_bytes(hello.random)
        push_opaque(buf, 1, hello.legacy_session_id)
        push_list(buf, 2, buf.push_uint16, hello.cipher_suites)
        push_list(buf, 1, buf.push_uint8, hello.legacy_compression_methods)

        # extensions
        with push_block(buf, 2):
            with push_extension(buf, ExtensionType.GREASE):
                pass

            with push_extension(buf, ExtensionType.KEY_SHARE):
                push_list(buf, 2, partial(push_key_share, buf), hello.key_share)

            with push_extension(buf, ExtensionType.SUPPORTED_VERSIONS):
                push_list(buf, 1, buf.push_uint16, hello.supported_versions)

            with push_extension(buf, ExtensionType.SIGNATURE_ALGORITHMS):
                push_list(buf, 2, buf.push_uint16, hello.signature_algorithms)

            with push_extension(buf, ExtensionType.SUPPORTED_GROUPS):
                push_list(buf, 2, buf.push_uint16, hello.supported_groups)

            if hello.psk_key_exchange_modes is not None:
                with push_extension(buf, ExtensionType.PSK_KEY_EXCHANGE_MODES):
                    push_list(buf, 1, buf.push_uint8, hello.psk_key_exchange_modes)

            if hello.server_name is not None:
                with push_extension(buf, ExtensionType.SERVER_NAME):
                    with push_block(buf, 2):
                        buf.push_uint8(0)
                        push_opaque(buf, 2, hello.server_name.encode("ascii"))

            if hello.alpn_protocols is not None:
                with push_extension(buf, ExtensionType.ALPN):
                    push_list(
                        buf, 2, partial(push_alpn_protocol, buf), hello.alpn_protocols
                    )

            for extension_type, extension_value in hello.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)

            if hello.early_data:
                with push_extension(buf, ExtensionType.EARLY_DATA):
                    pass

            with push_extension(buf, ExtensionType.STATUS_REQUEST):
                buf.push_uint8(1)  # OCSP
                with push_block(buf, 2):  # empty responder_id_list
                    pass
                with push_block(buf, 2):  # empty extensions
                    pass

            # pre_shared_key MUST be last
            if hello.pre_shared_key is not None:
                with push_extension(buf, ExtensionType.PRE_SHARED_KEY):
                    push_list(
                        buf,
                        2,
                        partial(push_psk_identity, buf),
                        hello.pre_shared_key.identities,
                    )
                    push_list(
                        buf,
                        2,
                        partial(push_psk_binder, buf),
                        hello.pre_shared_key.binders,
                    )


@dataclass
class ServerHello:
    random: bytes
    legacy_session_id: bytes
    cipher_suite: int
    compression_method: int

    # extensions
    key_share: KeyShareEntry | None = None
    pre_shared_key: int | None = None
    supported_version: int | None = None
    other_extensions: list[tuple[int, bytes]] = field(default_factory=list)


def pull_server_hello(buf: Buffer) -> ServerHello:
    assert buf.pull_uint8() == HandshakeType.SERVER_HELLO
    with pull_block(buf, 3):
        assert buf.pull_uint16() == TLS_VERSION_1_2

        hello = ServerHello(
            random=buf.pull_bytes(32),
            legacy_session_id=pull_opaque(buf, 1),
            cipher_suite=buf.pull_uint16(),
            compression_method=buf.pull_uint8(),
        )

        # extensions
        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.SUPPORTED_VERSIONS:
                hello.supported_version = buf.pull_uint16()
            elif extension_type == ExtensionType.KEY_SHARE:
                hello.key_share = pull_key_share(buf)
            elif extension_type == ExtensionType.PRE_SHARED_KEY:
                hello.pre_shared_key = buf.pull_uint16()
            else:
                hello.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return hello


def push_server_hello(buf: Buffer, hello: ServerHello) -> None:
    buf.push_uint8(HandshakeType.SERVER_HELLO)
    with push_block(buf, 3):
        buf.push_uint16(TLS_VERSION_1_2)
        buf.push_bytes(hello.random)

        push_opaque(buf, 1, hello.legacy_session_id)
        buf.push_uint16(hello.cipher_suite)
        buf.push_uint8(hello.compression_method)

        # extensions
        with push_block(buf, 2):
            if hello.supported_version is not None:
                with push_extension(buf, ExtensionType.SUPPORTED_VERSIONS):
                    buf.push_uint16(hello.supported_version)

            if hello.key_share is not None:
                with push_extension(buf, ExtensionType.KEY_SHARE):
                    push_key_share(buf, hello.key_share)

            if hello.pre_shared_key is not None:
                with push_extension(buf, ExtensionType.PRE_SHARED_KEY):
                    buf.push_uint16(hello.pre_shared_key)

            for extension_type, extension_value in hello.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


@dataclass
class NewSessionTicket:
    ticket_lifetime: int = 0
    ticket_age_add: int = 0
    ticket_nonce: bytes = b""
    ticket: bytes = b""

    # extensions
    max_early_data_size: int | None = None
    other_extensions: list[tuple[int, bytes]] = field(default_factory=list)


def pull_new_session_ticket(buf: Buffer) -> NewSessionTicket:
    new_session_ticket = NewSessionTicket()

    assert buf.pull_uint8() == HandshakeType.NEW_SESSION_TICKET
    with pull_block(buf, 3):
        new_session_ticket.ticket_lifetime = buf.pull_uint32()
        new_session_ticket.ticket_age_add = buf.pull_uint32()
        new_session_ticket.ticket_nonce = pull_opaque(buf, 1)
        new_session_ticket.ticket = pull_opaque(buf, 2)

        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.EARLY_DATA:
                new_session_ticket.max_early_data_size = buf.pull_uint32()
            else:
                new_session_ticket.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return new_session_ticket


def push_new_session_ticket(buf: Buffer, new_session_ticket: NewSessionTicket) -> None:
    buf.push_uint8(HandshakeType.NEW_SESSION_TICKET)
    with push_block(buf, 3):
        buf.push_uint32(new_session_ticket.ticket_lifetime)
        buf.push_uint32(new_session_ticket.ticket_age_add)
        push_opaque(buf, 1, new_session_ticket.ticket_nonce)
        push_opaque(buf, 2, new_session_ticket.ticket)

        with push_block(buf, 2):
            if new_session_ticket.max_early_data_size is not None:
                with push_extension(buf, ExtensionType.EARLY_DATA):
                    buf.push_uint32(new_session_ticket.max_early_data_size)

            for extension_type, extension_value in new_session_ticket.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


@dataclass
class EncryptedExtensions:
    alpn_protocol: str | None = None
    early_data: bool = False

    other_extensions: list[tuple[int, bytes]] = field(default_factory=list)


def pull_encrypted_extensions(buf: Buffer) -> EncryptedExtensions:
    extensions = EncryptedExtensions()

    assert buf.pull_uint8() == HandshakeType.ENCRYPTED_EXTENSIONS
    with pull_block(buf, 3):

        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.ALPN:
                extensions.alpn_protocol = pull_list(
                    buf, 2, partial(pull_alpn_protocol, buf)
                )[0]
            elif extension_type == ExtensionType.EARLY_DATA:
                extensions.early_data = True
            else:
                extensions.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return extensions


def push_encrypted_extensions(buf: Buffer, extensions: EncryptedExtensions) -> None:
    buf.push_uint8(HandshakeType.ENCRYPTED_EXTENSIONS)
    with push_block(buf, 3):
        with push_block(buf, 2):
            if extensions.alpn_protocol is not None:
                with push_extension(buf, ExtensionType.ALPN):
                    push_list(
                        buf,
                        2,
                        partial(push_alpn_protocol, buf),
                        [extensions.alpn_protocol],
                    )

            if extensions.early_data:
                with push_extension(buf, ExtensionType.EARLY_DATA):
                    pass

            for extension_type, extension_value in extensions.other_extensions:
                with push_extension(buf, extension_type):
                    buf.push_bytes(extension_value)


CertificateEntry = Tuple[bytes, bytes]


@dataclass
class Certificate:
    request_context: bytes = b""
    certificates: list[CertificateEntry] = field(default_factory=list)


@dataclass
class CertificateRequest:
    request_context: bytes = b""
    signature_algorithms: list[int] | None = None
    other_extensions: list[tuple[int, bytes]] = field(default_factory=list)


def pull_certificate(buf: Buffer) -> Certificate:
    certificate = Certificate()

    assert buf.pull_uint8() == HandshakeType.CERTIFICATE
    with pull_block(buf, 3):
        certificate.request_context = pull_opaque(buf, 1)

        def pull_certificate_entry(buf: Buffer) -> CertificateEntry:
            data = pull_opaque(buf, 3)
            extensions = pull_opaque(buf, 2)
            return (data, extensions)

        certificate.certificates = pull_list(
            buf, 3, partial(pull_certificate_entry, buf)
        )

    return certificate


def pull_certificate_request(buf: Buffer) -> CertificateRequest:
    certificate_request = CertificateRequest()

    assert buf.pull_uint8() == HandshakeType.CERTIFICATE_REQUEST
    with pull_block(buf, 3):
        certificate_request.request_context = pull_opaque(buf, 1)

        def pull_extension() -> None:
            extension_type = buf.pull_uint16()
            extension_length = buf.pull_uint16()
            if extension_type == ExtensionType.SIGNATURE_ALGORITHMS:
                certificate_request.signature_algorithms = pull_list(
                    buf, 2, buf.pull_uint16
                )
            else:
                certificate_request.other_extensions.append(
                    (extension_type, buf.pull_bytes(extension_length))
                )

        pull_list(buf, 2, pull_extension)

    return certificate_request


def push_certificate(buf: Buffer, certificate: Certificate) -> None:
    buf.push_uint8(HandshakeType.CERTIFICATE)
    with push_block(buf, 3):
        push_opaque(buf, 1, certificate.request_context)

        def push_certificate_entry(buf: Buffer, entry: CertificateEntry) -> None:
            push_opaque(buf, 3, entry[0])
            push_opaque(buf, 2, entry[1])

        push_list(
            buf, 3, partial(push_certificate_entry, buf), certificate.certificates
        )


@dataclass
class CertificateVerify:
    algorithm: int
    signature: bytes


def pull_certificate_verify(buf: Buffer) -> CertificateVerify:
    assert buf.pull_uint8() == HandshakeType.CERTIFICATE_VERIFY
    with pull_block(buf, 3):
        algorithm = buf.pull_uint16()
        signature = pull_opaque(buf, 2)

    return CertificateVerify(algorithm=algorithm, signature=signature)


def push_certificate_verify(buf: Buffer, verify: CertificateVerify) -> None:
    buf.push_uint8(HandshakeType.CERTIFICATE_VERIFY)
    with push_block(buf, 3):
        buf.push_uint16(verify.algorithm)
        push_opaque(buf, 2, verify.signature)


@dataclass
class Finished:
    verify_data: bytes = b""


def pull_finished(buf: Buffer) -> Finished:
    finished = Finished()

    assert buf.pull_uint8() == HandshakeType.FINISHED
    finished.verify_data = pull_opaque(buf, 3)

    return finished


def push_finished(buf: Buffer, finished: Finished) -> None:
    buf.push_uint8(HandshakeType.FINISHED)
    push_opaque(buf, 3, finished.verify_data)


class KeySchedule:
    def __init__(self, cipher_suite: CipherSuite):
        self.algorithm = cipher_suite_hash(cipher_suite)
        self.digest_size = int(self.algorithm / 8)
        self.cipher_suite = cipher_suite
        self.generation = 0
        self.hash = hashlib.new(f"sha{self.algorithm}")
        self.hash_empty_value = self.hash.copy().digest()
        self.secret = bytes(self.digest_size)

    def certificate_verify_data(self, context_string: bytes) -> bytes:
        return b" " * 64 + context_string + b"\x00" + self.hash.copy().digest()

    def finished_verify_data(self, secret: bytes) -> bytes:
        hmac_key = hkdf_expand_label(
            algorithm=self.algorithm,
            secret=secret,
            label=b"finished",
            hash_value=b"",
            length=self.digest_size,
        )

        h = HMAC(hmac_key, digestmod=f"sha{self.algorithm}")
        h.update(self.hash.copy().digest())
        return h.digest()

    def derive_secret(self, label: bytes) -> bytes:
        return hkdf_expand_label(
            algorithm=self.algorithm,
            secret=self.secret,
            label=label,
            hash_value=self.hash.copy().digest(),
            length=self.digest_size,
        )

    def extract(self, key_material: bytes | None = None) -> None:
        if key_material is None:
            key_material = bytes(self.digest_size)

        if self.generation:
            self.secret = hkdf_expand_label(
                algorithm=self.algorithm,
                secret=self.secret,
                label=b"derived",
                hash_value=self.hash_empty_value,
                length=self.digest_size,
            )

        self.generation += 1
        self.secret = hkdf_extract(
            algorithm=self.algorithm, salt=self.secret, key_material=key_material
        )

    def update_hash(self, data: bytes) -> None:
        self.hash.update(data)


class KeyScheduleProxy:
    def __init__(self, cipher_suites: list[CipherSuite]):
        self.__schedules = dict(map(lambda c: (c, KeySchedule(c)), cipher_suites))

    def extract(self, key_material: bytes | None = None) -> None:
        for k in self.__schedules.values():
            k.extract(key_material)

    def select(self, cipher_suite: CipherSuite) -> KeySchedule:
        return self.__schedules[cipher_suite]

    def update_hash(self, data: bytes) -> None:
        for k in self.__schedules.values():
            k.update_hash(data)


CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: 256,
    CipherSuite.AES_256_GCM_SHA384: 384,
    CipherSuite.CHACHA20_POLY1305_SHA256: 256,
}

SIGNATURE_ALGORITHMS: dict[SignatureAlgorithm, tuple[bool | None, int]] = {
    SignatureAlgorithm.ECDSA_SECP256R1_SHA256: (None, 256),
    SignatureAlgorithm.ECDSA_SECP384R1_SHA384: (None, 384),
    SignatureAlgorithm.ECDSA_SECP521R1_SHA512: (None, 512),
    SignatureAlgorithm.RSA_PKCS1_SHA256: (False, 256),
    SignatureAlgorithm.RSA_PKCS1_SHA384: (False, 384),
    SignatureAlgorithm.RSA_PKCS1_SHA512: (False, 512),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA256: (True, 256),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA384: (True, 384),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA512: (True, 512),
}


def cipher_suite_hash(cipher_suite: CipherSuite) -> int:
    return CIPHER_SUITES[cipher_suite]


def negotiate(
    supported: list[T],
    offered: list[Any] | None,
    exc: Alert | None = None,
    excl: T | None = None,
) -> T:
    if offered is not None:
        for c in supported:
            if c in offered:
                if excl is not None and excl == c:
                    continue
                return c

    if exc is not None:
        raise exc
    return None


def signature_algorithm_params(signature_algorithm: int) -> tuple[Any, ...]:
    if signature_algorithm in (SignatureAlgorithm.ED25519, SignatureAlgorithm.ED448):
        return ()

    is_pss, hash_size = SIGNATURE_ALGORITHMS[SignatureAlgorithm(signature_algorithm)]

    if is_pss is None:
        return ()

    return (
        is_pss,
        hash_size,
    )


@contextmanager
def push_message(
    key_schedule: KeySchedule | KeyScheduleProxy, buf: Buffer
) -> Generator:
    hash_start = buf.tell()
    yield
    key_schedule.update_hash(buf.data_slice(hash_start, buf.tell()))


# callback types


@dataclass
class SessionTicket:
    """
    A TLS session ticket for session resumption.
    """

    age_add: int
    cipher_suite: CipherSuite
    not_valid_after: datetime.datetime
    not_valid_before: datetime.datetime
    resumption_secret: bytes
    server_name: str
    ticket: bytes

    max_early_data_size: int | None = None
    other_extensions: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        now = utcnow()
        return now >= self.not_valid_before and now <= self.not_valid_after

    @property
    def obfuscated_age(self) -> int:
        age = int((utcnow() - self.not_valid_before).total_seconds() * 1000)
        return (age + self.age_add) % (1 << 32)


AlpnHandler = Callable[[str], None]
SessionTicketFetcher = Callable[[bytes], Optional[SessionTicket]]
SessionTicketHandler = Callable[[SessionTicket], None]


class Context:
    def __init__(
        self,
        is_client: bool,
        alpn_protocols: list[str] | None = None,
        cadata: bytes | None = None,
        cafile: str | None = None,
        capath: str | None = None,
        cipher_suites: list[CipherSuite] | None = None,
        logger: logging.Logger | logging.LoggerAdapter | None = None,
        max_early_data: int | None = None,
        server_name: str | None = None,
        verify_mode: int | None = None,
        hostname_checks_common_name: bool = False,
        assert_fingerprint: str | None = None,
        verify_hostname: bool = True,
    ):
        # configuration
        self._alpn_protocols = alpn_protocols
        self._cadata = cadata
        self._cafile = cafile
        self._capath = capath
        self._hostname_checks_common_name = hostname_checks_common_name
        self._assert_fingerprint = assert_fingerprint
        self._verify_hostname = verify_hostname
        self.certificate: X509Certificate | None = None
        self.certificate_chain: list[X509Certificate] = []
        self.certificate_private_key: (
            EcPrivateKey | Ed25519PrivateKey | DsaPrivateKey | RsaPrivateKey | None
        ) = None
        self.handshake_extensions: list[Extension] = []
        self._max_early_data = max_early_data
        self.session_ticket: SessionTicket | None = None

        # ensure pure ascii server name
        if server_name is not None and not server_name.isascii():
            server_name = idna_encode(server_name).decode()

        self._server_name = server_name

        if verify_mode is not None:
            self._verify_mode = verify_mode
        else:
            self._verify_mode = ssl.CERT_REQUIRED if is_client else ssl.CERT_NONE

        # callbacks
        self.alpn_cb: AlpnHandler | None = None
        self.get_session_ticket_cb: SessionTicketFetcher | None = None
        self.new_session_ticket_cb: SessionTicketHandler | None = None
        self.update_traffic_key_cb: Callable[
            [Direction, Epoch, CipherSuite, bytes], None
        ] = lambda d, e, c, s: None

        # supported parameters
        if cipher_suites is not None:
            self._cipher_suites = cipher_suites
        else:
            self._cipher_suites = [
                CipherSuite.GREASE,
                CipherSuite.AES_128_GCM_SHA256,
                CipherSuite.CHACHA20_POLY1305_SHA256,
                CipherSuite.AES_256_GCM_SHA384,
            ]
        self._legacy_compression_methods: list[int] = [CompressionMethod.NULL]
        self._psk_key_exchange_modes: list[int] = [PskKeyExchangeMode.PSK_DHE_KE]
        self._signature_algorithms: list[int] = [
            SignatureAlgorithm.ECDSA_SECP256R1_SHA256,
            SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
            SignatureAlgorithm.RSA_PKCS1_SHA256,
            SignatureAlgorithm.ECDSA_SECP384R1_SHA384,
            SignatureAlgorithm.RSA_PSS_RSAE_SHA384,
            SignatureAlgorithm.RSA_PKCS1_SHA384,
            SignatureAlgorithm.RSA_PSS_RSAE_SHA512,
            SignatureAlgorithm.RSA_PKCS1_SHA512,
            SignatureAlgorithm.ED25519,
        ]

        self._supported_groups = [
            Group.GREASE,
            Group.X25519ML768,
            Group.X25519,
            Group.SECP256R1,
            Group.SECP384R1,
        ]

        self._supported_versions = [TLS_VERSION_GREASE, TLS_VERSION_1_3]

        # state
        self.alpn_negotiated: str | None = None
        self.early_data_accepted: bool = False
        self.key_schedule: KeySchedule | None = None
        self.received_extensions: list[Extension] | None = None
        self._key_schedule_psk: KeySchedule | None = None
        self._key_schedule_proxy: KeyScheduleProxy | None = None
        self._new_session_ticket: NewSessionTicket | None = None
        self._peer_certificate: X509Certificate | None = None
        self._peer_certificate_chain: list[X509Certificate] = []
        self._ocsp_response: bytes | None = None
        self._receive_buffer = b""
        self._session_resumed = False
        self._enc_key: bytes | None = None
        self._dec_key: bytes | None = None
        self._certificate_request: CertificateRequest | None = None
        self.__logger = logger

        # KeyExchange
        self._ec_p256_private_key: ECDHP256KeyExchange | None = None
        self._ec_p384_private_key: ECDHP384KeyExchange | None = None
        self._ec_p521_private_key: ECDHP521KeyExchange | None = None
        self._x25519_private_key: X25519KeyExchange | None = None
        self._x25519_kyber_768_private_key: X25519ML768KeyExchange | None = None

        if is_client:
            self.client_random = os.urandom(32)
            self.legacy_session_id = b""
            self.state = State.CLIENT_HANDSHAKE_START
        else:
            self.client_random = None
            self.legacy_session_id = None
            self.state = State.SERVER_EXPECT_CLIENT_HELLO

    @property
    def peer_certificate(self) -> X509Certificate | None:
        return self._peer_certificate

    @property
    def peer_certificate_chain(self) -> list[X509Certificate]:
        return self._peer_certificate_chain

    @property
    def session_resumed(self) -> bool:
        """
        Returns True if session resumption was successfully used.
        """
        return self._session_resumed

    def handle_message(
        self, input_data: bytes, output_buf: dict[Epoch, Buffer]
    ) -> None:
        if self.state == State.CLIENT_HANDSHAKE_START:
            self._client_send_hello(output_buf[Epoch.INITIAL])
            return

        self._receive_buffer += input_data
        while len(self._receive_buffer) >= 4:
            # determine message length
            message_type = self._receive_buffer[0]
            message_length = 4 + int.from_bytes(
                self._receive_buffer[1:4], byteorder="big"
            )

            # check message is complete
            if len(self._receive_buffer) < message_length:
                break
            message = self._receive_buffer[:message_length]
            self._receive_buffer = self._receive_buffer[message_length:]

            input_buf = Buffer(data=message)

            # client states

            if self.state == State.CLIENT_EXPECT_SERVER_HELLO:
                if message_type == HandshakeType.SERVER_HELLO:
                    self._client_handle_hello(input_buf, output_buf[Epoch.INITIAL])
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS:
                if message_type == HandshakeType.ENCRYPTED_EXTENSIONS:
                    self._client_handle_encrypted_extensions(input_buf)
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE:
                if message_type == HandshakeType.CERTIFICATE:
                    self._client_handle_certificate(input_buf)
                elif message_type == HandshakeType.CERTIFICATE_REQUEST:
                    self._client_handle_certificate_request(input_buf)
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.CLIENT_EXPECT_CERTIFICATE_VERIFY:
                if message_type == HandshakeType.CERTIFICATE_VERIFY:
                    self._client_handle_certificate_verify(input_buf)
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.CLIENT_EXPECT_FINISHED:
                if message_type == HandshakeType.FINISHED:
                    self._client_handle_finished(input_buf, output_buf[Epoch.HANDSHAKE])
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.CLIENT_POST_HANDSHAKE:
                if message_type == HandshakeType.NEW_SESSION_TICKET:
                    self._client_handle_new_session_ticket(input_buf)
                else:
                    raise AlertUnexpectedMessage

            # server states

            elif self.state == State.SERVER_EXPECT_CLIENT_HELLO:
                if message_type == HandshakeType.CLIENT_HELLO:
                    self._server_handle_hello(
                        input_buf,
                        output_buf[Epoch.INITIAL],
                        output_buf[Epoch.HANDSHAKE],
                        output_buf[Epoch.ONE_RTT],
                    )
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.SERVER_EXPECT_FINISHED:
                if message_type == HandshakeType.FINISHED:
                    self._server_handle_finished(input_buf, output_buf[Epoch.ONE_RTT])
                else:
                    raise AlertUnexpectedMessage
            elif self.state == State.SERVER_POST_HANDSHAKE:
                raise AlertUnexpectedMessage

            assert input_buf.eof()

    def _build_session_ticket(
        self, new_session_ticket: NewSessionTicket, other_extensions: list[Extension]
    ) -> SessionTicket:
        resumption_master_secret = self.key_schedule.derive_secret(b"res master")
        resumption_secret = hkdf_expand_label(
            algorithm=self.key_schedule.algorithm,
            secret=resumption_master_secret,
            label=b"resumption",
            hash_value=new_session_ticket.ticket_nonce,
            length=self.key_schedule.digest_size,
        )

        timestamp = utcnow()
        return SessionTicket(
            age_add=new_session_ticket.ticket_age_add,
            cipher_suite=self.key_schedule.cipher_suite,
            max_early_data_size=new_session_ticket.max_early_data_size,
            not_valid_after=timestamp
            + datetime.timedelta(seconds=new_session_ticket.ticket_lifetime),
            not_valid_before=timestamp,
            other_extensions=other_extensions,
            resumption_secret=resumption_secret,
            server_name=self._server_name,
            ticket=new_session_ticket.ticket,
        )

    def _client_send_hello(self, output_buf: Buffer) -> None:
        key_share: list[KeyShareEntry] = []
        supported_groups: list[int] = []

        for group in self._supported_groups:
            if group == Group.SECP256R1:
                self._ec_p256_private_key = ECDHP256KeyExchange()
                key_share.append(
                    (Group.SECP256R1, self._ec_p256_private_key.public_key())
                )
                supported_groups.append(Group.SECP256R1)
            elif group == Group.SECP384R1:
                self._ec_p384_private_key = ECDHP384KeyExchange()
                key_share.append(
                    (Group.SECP384R1, self._ec_p384_private_key.public_key())
                )
                supported_groups.append(Group.SECP384R1)
            elif group == Group.SECP521R1:
                self._ec_p521_private_key = ECDHP521KeyExchange()
                key_share.append(
                    (Group.SECP521R1, self._ec_p521_private_key.public_key())
                )
                supported_groups.append(Group.SECP521R1)
            elif group == Group.X25519:
                self._x25519_private_key = X25519KeyExchange()
                key_share.append((Group.X25519, self._x25519_private_key.public_key()))
                supported_groups.append(Group.X25519)
            elif group == Group.X25519ML768:
                self._x25519_kyber_768_private_key = X25519ML768KeyExchange()
                key_share.append(
                    (
                        Group.X25519ML768,
                        self._x25519_kyber_768_private_key.public_key(),
                    )
                )
                supported_groups.append(Group.X25519ML768)
                if self.__logger is not None:
                    self.__logger.debug(
                        "TLS: Advertising to peer post-quantum algorithm "
                        "using X25519ML768 (0x11EC)"
                    )
            elif group == Group.GREASE:
                key_share.append((Group.GREASE, b"\x00"))
                supported_groups.append(Group.GREASE)

        assert len(key_share), "no key share entries"

        hello = ClientHello(
            random=self.client_random,
            legacy_session_id=self.legacy_session_id,
            cipher_suites=[int(x) for x in self._cipher_suites],
            legacy_compression_methods=self._legacy_compression_methods,
            alpn_protocols=self._alpn_protocols,
            key_share=key_share,
            psk_key_exchange_modes=(
                self._psk_key_exchange_modes
                if (self.session_ticket or self.new_session_ticket_cb is not None)
                else None
            ),
            server_name=self._server_name,
            signature_algorithms=self._signature_algorithms,
            supported_groups=supported_groups,
            supported_versions=self._supported_versions,
            other_extensions=self.handshake_extensions,
        )

        # PSK
        if self.session_ticket and self.session_ticket.is_valid:
            self._key_schedule_psk = KeySchedule(self.session_ticket.cipher_suite)
            self._key_schedule_psk.extract(self.session_ticket.resumption_secret)
            binder_key = self._key_schedule_psk.derive_secret(b"res binder")
            binder_length = self._key_schedule_psk.digest_size

            # update hello
            if self.session_ticket.max_early_data_size is not None:
                hello.early_data = True
            hello.pre_shared_key = OfferedPsks(
                identities=[
                    (self.session_ticket.ticket, self.session_ticket.obfuscated_age)
                ],
                binders=[bytes(binder_length)],
            )

            # serialize hello without binder
            tmp_buf = Buffer(capacity=2048)
            push_client_hello(tmp_buf, hello)

            # calculate binder
            hash_offset = tmp_buf.tell() - binder_length - 3
            self._key_schedule_psk.update_hash(tmp_buf.data_slice(0, hash_offset))
            binder = self._key_schedule_psk.finished_verify_data(binder_key)
            hello.pre_shared_key.binders[0] = binder
            self._key_schedule_psk.update_hash(
                tmp_buf.data_slice(hash_offset, hash_offset + 3) + binder
            )

            # calculate early data key
            if hello.early_data:
                early_key = self._key_schedule_psk.derive_secret(b"c e traffic")
                self.update_traffic_key_cb(
                    Direction.ENCRYPT,
                    Epoch.ZERO_RTT,
                    self._key_schedule_psk.cipher_suite,
                    early_key,
                )

        self._key_schedule_proxy = KeyScheduleProxy(
            [cs for cs in self._cipher_suites if cs != CipherSuite.GREASE]
        )
        self._key_schedule_proxy.extract(None)

        with push_message(self._key_schedule_proxy, output_buf):
            push_client_hello(output_buf, hello)

        self._set_state(State.CLIENT_EXPECT_SERVER_HELLO)

    def _client_handle_hello(self, input_buf: Buffer, output_buf: Buffer) -> None:
        peer_hello = pull_server_hello(input_buf)

        cipher_suite = negotiate(
            self._cipher_suites,
            [peer_hello.cipher_suite],
            AlertHandshakeFailure("Unsupported cipher suite"),
            excl=CipherSuite.GREASE,
        )
        assert peer_hello.compression_method in self._legacy_compression_methods
        assert peer_hello.supported_version in self._supported_versions

        # select key schedule
        if peer_hello.pre_shared_key is not None:
            if (
                self._key_schedule_psk is None
                or peer_hello.pre_shared_key != 0
                or cipher_suite != self._key_schedule_psk.cipher_suite
            ):
                raise AlertIllegalParameter
            self.key_schedule = self._key_schedule_psk
            self._session_resumed = True
        else:
            self.key_schedule = self._key_schedule_proxy.select(cipher_suite)
        self._key_schedule_psk = None
        self._key_schedule_proxy = None

        # perform key exchange
        peer_public_key = peer_hello.key_share[1]
        shared_key: bytes | None = None

        if (
            peer_hello.key_share[0] == Group.X25519
            and self._x25519_private_key is not None
        ):
            shared_key = self._x25519_private_key.exchange(peer_public_key)
        elif peer_hello.key_share[0] == Group.X25519ML768:
            shared_key = self._x25519_kyber_768_private_key.exchange(peer_public_key)
            if self.__logger is not None:
                self.__logger.debug(
                    "TLS: Post-quantum safety achieved using X25519ML768 (key-exchange)"
                )
        elif (
            peer_hello.key_share[0] == Group.SECP256R1
            and self._ec_p256_private_key is not None
        ):
            shared_key = self._ec_p256_private_key.exchange(peer_public_key)
        elif (
            peer_hello.key_share[0] == Group.SECP384R1
            and self._ec_p384_private_key is not None
        ):
            shared_key = self._ec_p384_private_key.exchange(peer_public_key)
        elif (
            peer_hello.key_share[0] == Group.SECP521R1
            and self._ec_p521_private_key is not None
        ):
            shared_key = self._ec_p521_private_key.exchange(peer_public_key)

        assert shared_key is not None

        self.key_schedule.update_hash(input_buf.data)
        self.key_schedule.extract(shared_key)

        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.HANDSHAKE, b"s hs traffic"
        )

        self._set_state(State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS)

    def _client_handle_encrypted_extensions(self, input_buf: Buffer) -> None:
        encrypted_extensions = pull_encrypted_extensions(input_buf)

        self.alpn_negotiated = encrypted_extensions.alpn_protocol
        self.early_data_accepted = encrypted_extensions.early_data
        self.received_extensions = encrypted_extensions.other_extensions
        if self.alpn_cb:
            self.alpn_cb(self.alpn_negotiated)

        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.HANDSHAKE, b"c hs traffic"
        )
        self.key_schedule.update_hash(input_buf.data)

        # if the server accepted our PSK we are done, other we want its certificate
        if self._session_resumed:
            self._set_state(State.CLIENT_EXPECT_FINISHED)
        else:
            self._set_state(State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE)

    def _client_handle_certificate(self, input_buf: Buffer) -> None:
        certificate = pull_certificate(input_buf)

        # attempt to extract a possible OCSP staple extension from
        # the leaf certificate only.
        ext_buf = Buffer(data=certificate.certificates[0][1])

        try:
            # RFC 8446, Section 4.4.2.2

            while not ext_buf.eof():
                ext_type = ext_buf.pull_uint16()
                ext_len = ext_buf.pull_uint16()

                if ext_type == ExtensionType.STATUS_REQUEST:
                    status_type = ext_buf.pull_uint8()
                    if status_type == 1:
                        resp_len = ext_buf.pull_uint24()
                        self._ocsp_response = ext_buf.pull_bytes(resp_len)
                        break
                    else:
                        ext_buf.pull_bytes(ext_len - 1)
                else:
                    break
        except BufferReadError:
            pass  # Defensive: against malformed extensions.

        self._peer_certificate = X509Certificate(certificate.certificates[0][0])
        self._peer_certificate_chain = [
            X509Certificate(certificate.certificates[i][0])
            for i in range(1, len(certificate.certificates))
        ]

        self.key_schedule.update_hash(input_buf.data)

        self._set_state(State.CLIENT_EXPECT_CERTIFICATE_VERIFY)

    def _client_handle_certificate_request(self, input_buf: Buffer) -> None:
        self._certificate_request = pull_certificate_request(input_buf)
        self.key_schedule.update_hash(input_buf.data)
        self._set_state(State.CLIENT_EXPECT_CERTIFICATE_REQUEST_OR_CERTIFICATE)

    def _client_handle_certificate_verify(self, input_buf: Buffer) -> None:
        verify = pull_certificate_verify(input_buf)

        assert verify.algorithm in self._signature_algorithms

        # check signature
        try:
            verify_with_public_key(
                self._peer_certificate.public_key(),
                verify.algorithm,
                self.key_schedule.certificate_verify_data(
                    b"TLS 1.3, server CertificateVerify"
                ),
                verify.signature,
            )
        except SignatureError as e:
            raise AlertDecryptError(str(e))

        # check certificate
        if self._verify_mode != ssl.CERT_NONE:
            verify_certificate(
                cadata=self._cadata,
                cafile=self._cafile,
                capath=self._capath,
                certificate=self._peer_certificate,
                chain=self._peer_certificate_chain,
                server_name=self._server_name,
                assert_server_name=self._verify_hostname,
                ocsp_response=self._ocsp_response,
            )

        if self._assert_fingerprint is not None:
            fingerprint = self._assert_fingerprint.replace(":", "").lower()
            digest_length = len(fingerprint)
            hashfunc = HASHFUNC_MAP.get(digest_length)

            if not hashfunc:
                raise AlertBadCertificate(
                    f"Fingerprint of invalid length: {fingerprint}"
                )

            expect_fingerprint = unhexlify(fingerprint.encode())
            peer_fingerprint = hashfunc(self._peer_certificate.public_bytes()).digest()

            if peer_fingerprint != expect_fingerprint:
                raise AlertBadCertificate(
                    "Fingerprints did not match. "
                    f'Expected "{expect_fingerprint.hex()}", '
                    f'got "{peer_fingerprint.hex()}"'
                )

        self.key_schedule.update_hash(input_buf.data)

        self._set_state(State.CLIENT_EXPECT_FINISHED)

    def _client_handle_finished(self, input_buf: Buffer, output_buf: Buffer) -> None:
        finished = pull_finished(input_buf)

        # check verify data
        expected_verify_data = self.key_schedule.finished_verify_data(self._dec_key)
        if finished.verify_data != expected_verify_data:
            raise AlertDecryptError
        self.key_schedule.update_hash(input_buf.data)

        # prepare traffic keys
        assert self.key_schedule.generation == 2
        self.key_schedule.extract(None)
        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.ONE_RTT, b"s ap traffic"
        )
        next_enc_key = self.key_schedule.derive_secret(b"c ap traffic")

        if self._certificate_request is not None:
            with push_message(self.key_schedule, output_buf):
                push_certificate(
                    output_buf,
                    Certificate(
                        request_context=self._certificate_request.request_context,
                        certificates=[
                            (cert.public_bytes(), b"")
                            for cert in [self.certificate] + self.certificate_chain
                            if cert is not None
                        ],
                    ),
                )

            if None not in (self.certificate, self.certificate_private_key):
                # determine applicable signature algorithms
                signature_algorithms: list[SignatureAlgorithm] = []

                if isinstance(self.certificate_private_key, RsaPrivateKey):
                    signature_algorithms = [
                        SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
                        SignatureAlgorithm.RSA_PKCS1_SHA256,
                    ]
                elif isinstance(self.certificate_private_key, EcPrivateKey):
                    if self.certificate_private_key.curve_type == 256:
                        signature_algorithms = [
                            SignatureAlgorithm.ECDSA_SECP256R1_SHA256
                        ]
                    elif self.certificate_private_key.curve_type == 384:
                        signature_algorithms = [
                            SignatureAlgorithm.ECDSA_SECP384R1_SHA384
                        ]
                    elif self.certificate_private_key.curve_type == 521:
                        signature_algorithms = [
                            SignatureAlgorithm.ECDSA_SECP521R1_SHA512
                        ]
                elif isinstance(self.certificate_private_key, Ed25519PrivateKey):
                    signature_algorithms = [SignatureAlgorithm.ED25519]

                signature_algorithm = negotiate(
                    signature_algorithms,
                    self._certificate_request.signature_algorithms,
                    AlertHandshakeFailure("No supported signature algorithm"),
                )

                signature = self.certificate_private_key.sign(
                    self.key_schedule.certificate_verify_data(
                        b"TLS 1.3, client CertificateVerify"
                    ),
                    *signature_algorithm_params(signature_algorithm),
                )

                with push_message(self.key_schedule, output_buf):
                    push_certificate_verify(
                        output_buf,
                        CertificateVerify(
                            algorithm=signature_algorithm, signature=signature
                        ),
                    )

        # send finished
        with push_message(self.key_schedule, output_buf):
            push_finished(
                output_buf,
                Finished(
                    verify_data=self.key_schedule.finished_verify_data(self._enc_key)
                ),
            )

        # commit traffic key
        self._enc_key = next_enc_key
        self.update_traffic_key_cb(
            Direction.ENCRYPT,
            Epoch.ONE_RTT,
            self.key_schedule.cipher_suite,
            self._enc_key,
        )

        self._set_state(State.CLIENT_POST_HANDSHAKE)

    def _client_handle_new_session_ticket(self, input_buf: Buffer) -> None:
        new_session_ticket = pull_new_session_ticket(input_buf)

        # notify application
        if self.new_session_ticket_cb is not None:
            ticket = self._build_session_ticket(
                new_session_ticket, self.received_extensions
            )
            self.new_session_ticket_cb(ticket)

    def _server_handle_hello(
        self,
        input_buf: Buffer,
        initial_buf: Buffer,
        handshake_buf: Buffer,
        onertt_buf: Buffer,
    ) -> None:
        peer_hello = pull_client_hello(input_buf)

        # determine applicable signature algorithms
        signature_algorithms: list[SignatureAlgorithm] = []

        if isinstance(self.certificate_private_key, RsaPrivateKey):
            signature_algorithms = [
                SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAlgorithm.RSA_PKCS1_SHA256,
            ]
        elif isinstance(self.certificate_private_key, EcPrivateKey):
            if self.certificate_private_key.curve_type == 256:
                signature_algorithms = [SignatureAlgorithm.ECDSA_SECP256R1_SHA256]
            elif self.certificate_private_key.curve_type == 384:
                signature_algorithms = [SignatureAlgorithm.ECDSA_SECP384R1_SHA384]
            elif self.certificate_private_key.curve_type == 521:
                signature_algorithms = [SignatureAlgorithm.ECDSA_SECP521R1_SHA512]
        elif isinstance(self.certificate_private_key, Ed25519PrivateKey):
            signature_algorithms = [SignatureAlgorithm.ED25519]

        # negotiate parameters
        cipher_suite = negotiate(
            self._cipher_suites,
            peer_hello.cipher_suites,
            AlertHandshakeFailure("No supported cipher suite"),
            excl=CipherSuite.GREASE,
        )
        compression_method = negotiate(
            self._legacy_compression_methods,
            peer_hello.legacy_compression_methods,
            AlertHandshakeFailure("No supported compression method"),
        )
        psk_key_exchange_mode = negotiate(
            self._psk_key_exchange_modes, peer_hello.psk_key_exchange_modes
        )
        signature_algorithm = negotiate(
            signature_algorithms,
            peer_hello.signature_algorithms,
            AlertHandshakeFailure("No supported signature algorithm"),
        )
        supported_version = negotiate(
            self._supported_versions,
            peer_hello.supported_versions,
            AlertProtocolVersion("No supported protocol version"),
        )

        # negotiate ALPN
        if self._alpn_protocols is not None:
            self.alpn_negotiated = negotiate(
                self._alpn_protocols,
                peer_hello.alpn_protocols,
                AlertHandshakeFailure("No common ALPN protocols"),
            )

        self.client_random = peer_hello.random
        self.server_random = os.urandom(32)
        self.legacy_session_id = peer_hello.legacy_session_id
        self.received_extensions = peer_hello.other_extensions

        if self.alpn_cb:
            self.alpn_cb(self.alpn_negotiated)

        # select key schedule
        pre_shared_key = None
        if (
            self.get_session_ticket_cb is not None
            and psk_key_exchange_mode is not None
            and peer_hello.pre_shared_key is not None
            and len(peer_hello.pre_shared_key.identities) == 1
            and len(peer_hello.pre_shared_key.binders) == 1
        ):
            # ask application to find session ticket
            identity = peer_hello.pre_shared_key.identities[0]
            session_ticket = self.get_session_ticket_cb(identity[0])

            # validate session ticket
            if (
                session_ticket is not None
                and session_ticket.is_valid
                and session_ticket.cipher_suite == cipher_suite
            ):
                self.key_schedule = KeySchedule(cipher_suite)
                self.key_schedule.extract(session_ticket.resumption_secret)

                binder_key = self.key_schedule.derive_secret(b"res binder")
                binder_length = self.key_schedule.digest_size

                hash_offset = input_buf.tell() - binder_length - 3
                binder = input_buf.data_slice(
                    hash_offset + 3, hash_offset + 3 + binder_length
                )

                self.key_schedule.update_hash(input_buf.data_slice(0, hash_offset))
                expected_binder = self.key_schedule.finished_verify_data(binder_key)

                if binder != expected_binder:
                    raise AlertHandshakeFailure("PSK validation failed")

                self.key_schedule.update_hash(
                    input_buf.data_slice(hash_offset, hash_offset + 3 + binder_length)
                )
                self._session_resumed = True

                # calculate early data key
                if peer_hello.early_data:
                    early_key = self.key_schedule.derive_secret(b"c e traffic")
                    self.early_data_accepted = True
                    self.update_traffic_key_cb(
                        Direction.DECRYPT,
                        Epoch.ZERO_RTT,
                        self.key_schedule.cipher_suite,
                        early_key,
                    )

                pre_shared_key = 0

        # if PSK is not used, initialize key schedule
        if pre_shared_key is None:
            self.key_schedule = KeySchedule(cipher_suite)
            self.key_schedule.extract(None)
            self.key_schedule.update_hash(input_buf.data)

        # perform key exchange
        public_key: bytes | None = None
        group_kx: Group | None = None
        shared_key: bytes | None = None

        for key_share in peer_hello.key_share:
            peer_public_key = key_share[1]

            if key_share[0] == Group.X25519:
                self._x25519_private_key = X25519KeyExchange()
                public_key = self._x25519_private_key.public_key()
                shared_key = self._x25519_private_key.exchange(peer_public_key)
                group_kx = Group.X25519
                break
            elif key_share[0] == Group.X25519ML768:
                self._x25519_kyber_768_private_key = X25519ML768KeyExchange()
                shared_key = self._x25519_kyber_768_private_key.exchange(
                    peer_public_key
                )
                public_key = self._x25519_kyber_768_private_key.shared_ciphertext()
                group_kx = Group.X25519ML768
                break
            elif key_share[0] == Group.SECP256R1:
                self._ec_p256_private_key = ECDHP256KeyExchange()
                public_key = self._ec_p256_private_key.public_key()
                shared_key = self._ec_p256_private_key.exchange(peer_public_key)
                group_kx = Group.SECP256R1
                break
            elif key_share[0] == Group.SECP384R1:
                self._ec_p384_private_key = ECDHP384KeyExchange()
                public_key = self._ec_p384_private_key.public_key()
                shared_key = self._ec_p384_private_key.exchange(peer_public_key)
                group_kx = Group.SECP384R1
                break
            elif key_share[0] == Group.SECP521R1:
                self._ec_p521_private_key = ECDHP521KeyExchange()
                public_key = self._ec_p521_private_key.public_key()
                shared_key = self._ec_p521_private_key.exchange(peer_public_key)
                group_kx = Group.SECP521R1
                break

        assert shared_key is not None

        # send hello
        hello = ServerHello(
            random=self.server_random,
            legacy_session_id=self.legacy_session_id,
            cipher_suite=cipher_suite,
            compression_method=compression_method,
            key_share=(group_kx, public_key),
            pre_shared_key=pre_shared_key,
            supported_version=supported_version,
        )
        with push_message(self.key_schedule, initial_buf):
            push_server_hello(initial_buf, hello)
        self.key_schedule.extract(shared_key)

        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.HANDSHAKE, b"s hs traffic"
        )
        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.HANDSHAKE, b"c hs traffic"
        )

        # send encrypted extensions
        with push_message(self.key_schedule, handshake_buf):
            push_encrypted_extensions(
                handshake_buf,
                EncryptedExtensions(
                    alpn_protocol=self.alpn_negotiated,
                    early_data=self.early_data_accepted,
                    other_extensions=self.handshake_extensions,
                ),
            )

        if pre_shared_key is None:
            # send certificate
            with push_message(self.key_schedule, handshake_buf):
                push_certificate(
                    handshake_buf,
                    Certificate(
                        request_context=b"",
                        certificates=[
                            (x.public_bytes(), b"")
                            for x in [self.certificate] + self.certificate_chain
                        ],
                    ),
                )

            # send certificate verify
            signature = self.certificate_private_key.sign(
                self.key_schedule.certificate_verify_data(
                    b"TLS 1.3, server CertificateVerify"
                ),
                *signature_algorithm_params(signature_algorithm),
            )
            with push_message(self.key_schedule, handshake_buf):
                push_certificate_verify(
                    handshake_buf,
                    CertificateVerify(
                        algorithm=signature_algorithm, signature=signature
                    ),
                )

        # send finished
        with push_message(self.key_schedule, handshake_buf):
            push_finished(
                handshake_buf,
                Finished(
                    verify_data=self.key_schedule.finished_verify_data(self._enc_key)
                ),
            )

        # prepare traffic keys
        assert self.key_schedule.generation == 2
        self.key_schedule.extract(None)
        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.ONE_RTT, b"s ap traffic"
        )
        self._next_dec_key = self.key_schedule.derive_secret(b"c ap traffic")

        # anticipate client's FINISHED as we don't use client auth
        self._expected_verify_data = self.key_schedule.finished_verify_data(
            self._dec_key
        )
        buf = Buffer(capacity=64)
        push_finished(buf, Finished(verify_data=self._expected_verify_data))
        self.key_schedule.update_hash(buf.data)

        # create a new session ticket
        if self.new_session_ticket_cb is not None and psk_key_exchange_mode is not None:
            self._new_session_ticket = NewSessionTicket(
                ticket_lifetime=86400,
                ticket_age_add=struct.unpack("I", os.urandom(4))[0],
                ticket_nonce=b"",
                ticket=os.urandom(64),
                max_early_data_size=self._max_early_data,
            )

            # send message
            push_new_session_ticket(onertt_buf, self._new_session_ticket)

            # notify application
            ticket = self._build_session_ticket(
                self._new_session_ticket, self.handshake_extensions
            )
            self.new_session_ticket_cb(ticket)

        self._set_state(State.SERVER_EXPECT_FINISHED)

    def _server_handle_finished(self, input_buf: Buffer, output_buf: Buffer) -> None:
        finished = pull_finished(input_buf)

        # check verify data
        if finished.verify_data != self._expected_verify_data:
            raise AlertDecryptError

        # commit traffic key
        self._dec_key = self._next_dec_key
        self._next_dec_key = None
        self.update_traffic_key_cb(
            Direction.DECRYPT,
            Epoch.ONE_RTT,
            self.key_schedule.cipher_suite,
            self._dec_key,
        )

        self._set_state(State.SERVER_POST_HANDSHAKE)

    def _setup_traffic_protection(
        self, direction: Direction, epoch: Epoch, label: bytes
    ) -> None:
        key = self.key_schedule.derive_secret(label)

        if direction == Direction.ENCRYPT:
            self._enc_key = key
        else:
            self._dec_key = key

        self.update_traffic_key_cb(
            direction, epoch, self.key_schedule.cipher_suite, key
        )

    def _set_state(self, state: State) -> None:
        if self.__logger:
            self.__logger.debug("TLS %s -> %s", self.state.name, state.name)
        self.state = state
