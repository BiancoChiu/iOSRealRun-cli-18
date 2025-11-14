from __future__ import annotations

import binascii
from typing import Callable

from .._hazmat import (
    AeadAes128Gcm,
    AeadAes256Gcm,
    AeadChaCha20Poly1305,
    CryptoError,
    decode_packet_number,
)
from .._hazmat import QUICHeaderProtection as HeaderProtection
from ..tls import CipherSuite, cipher_suite_hash, hkdf_expand_label, hkdf_extract
from .packet import (
    QuicProtocolVersion,
    is_long_header,
)

CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: (b"aes-128-ecb", b"aes-128-gcm"),
    CipherSuite.CHACHA20_POLY1305_SHA256: (b"chacha20", b"chacha20-poly1305"),
    CipherSuite.AES_256_GCM_SHA384: (b"aes-256-ecb", b"aes-256-gcm"),
}
INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_VERSION_2 = binascii.unhexlify("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SAMPLE_SIZE = 16


Callback = Callable[[str], None]


def NoCallback(trigger: str) -> None:
    pass


class KeyUnavailableError(CryptoError):
    pass


def derive_key_iv_hp(
    *, cipher_suite: CipherSuite, secret: bytes, version: int
) -> tuple[bytes, bytes, bytes]:
    algorithm = cipher_suite_hash(cipher_suite)

    if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        CipherSuite.CHACHA20_POLY1305_SHA256,
    ]:
        key_size = 32
    else:
        key_size = 16

    if version == QuicProtocolVersion.VERSION_2:
        return (
            hkdf_expand_label(algorithm, secret, b"quicv2 key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quicv2 iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quicv2 hp", b"", key_size),
        )
    else:
        return (
            hkdf_expand_label(algorithm, secret, b"quic key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quic hp", b"", key_size),
        )


class CryptoContext:
    __slots__ = (
        "aead",
        "cipher_suite",
        "hp",
        "key_phase",
        "secret",
        "version",
        "_setup_cb",
        "_teardown_cb",
    )

    def __init__(
        self,
        key_phase: int = 0,
        setup_cb: Callback = NoCallback,
        teardown_cb: Callback = NoCallback,
    ) -> None:
        self.aead: AeadChaCha20Poly1305 | AeadAes128Gcm | AeadAes256Gcm | None = None
        self.cipher_suite: CipherSuite | None = None
        self.hp: HeaderProtection | None = None
        self.key_phase = key_phase
        self.secret: bytes | None = None
        self.version: int | None = None
        self._setup_cb = setup_cb
        self._teardown_cb = teardown_cb

    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int, bool]:
        if self.aead is None:
            raise KeyUnavailableError("Decryption key is not available")

        # header protection
        plain_header, packet_number = self.hp.remove(packet, encrypted_offset)
        first_byte = plain_header[0]

        # packet number
        pn_length = (first_byte & 0x03) + 1
        packet_number = decode_packet_number(
            packet_number, pn_length * 8, expected_packet_number
        )

        # detect key phase change
        crypto = self
        if not is_long_header(first_byte):
            key_phase = (first_byte & 4) >> 2
            if key_phase != self.key_phase:
                crypto = next_key_phase(self)

        # payload protection
        payload = crypto.aead.decrypt(
            packet_number, packet[len(plain_header) :], plain_header
        )

        return plain_header, payload, packet_number, crypto != self

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        assert self.is_valid(), "Encryption key is not available"

        # payload protection
        protected_payload = self.aead.encrypt(
            packet_number, plain_payload, plain_header
        )

        # header protection
        return self.hp.apply(plain_header, protected_payload)

    def is_valid(self) -> bool:
        return self.aead is not None

    def setup(self, *, cipher_suite: CipherSuite, secret: bytes, version: int) -> None:
        hp_cipher_name, aead_cipher_name = CIPHER_SUITES[cipher_suite]

        key, iv, hp = derive_key_iv_hp(
            cipher_suite=cipher_suite,
            secret=secret,
            version=version,
        )

        if aead_cipher_name == b"chacha20-poly1305":
            self.aead = AeadChaCha20Poly1305(key, iv)
        elif aead_cipher_name == b"aes-256-gcm":
            self.aead = AeadAes256Gcm(key, iv)
        elif aead_cipher_name == b"aes-128-gcm":
            self.aead = AeadAes128Gcm(key, iv)
        else:
            raise CryptoError(f"Invalid cipher name: {aead_cipher_name.decode()}")

        self.cipher_suite = cipher_suite
        self.hp = HeaderProtection(hp_cipher_name.decode(), hp)
        self.secret = secret
        self.version = version

        # trigger callback
        self._setup_cb("tls")

    def teardown(self) -> None:
        self.aead = None
        self.cipher_suite = None
        self.hp = None
        self.secret = None

        # trigger callback
        self._teardown_cb("tls")


def apply_key_phase(self: CryptoContext, crypto: CryptoContext, trigger: str) -> None:
    self.aead = crypto.aead
    self.key_phase = crypto.key_phase
    self.secret = crypto.secret

    # trigger callback
    self._setup_cb(trigger)


def next_key_phase(self: CryptoContext) -> CryptoContext:
    algorithm = cipher_suite_hash(self.cipher_suite)

    crypto = CryptoContext(key_phase=int(not self.key_phase))
    crypto.setup(
        cipher_suite=self.cipher_suite,
        secret=hkdf_expand_label(
            algorithm, self.secret, b"quic ku", b"", int(algorithm / 8)
        ),
        version=self.version,
    )
    return crypto


class CryptoPair:
    __slots__ = (
        "aead_tag_size",
        "recv",
        "send",
        "_update_key_requested",
    )

    def __init__(
        self,
        recv_setup_cb: Callback = NoCallback,
        recv_teardown_cb: Callback = NoCallback,
        send_setup_cb: Callback = NoCallback,
        send_teardown_cb: Callback = NoCallback,
    ) -> None:
        self.aead_tag_size = 16
        self.recv = CryptoContext(setup_cb=recv_setup_cb, teardown_cb=recv_teardown_cb)
        self.send = CryptoContext(setup_cb=send_setup_cb, teardown_cb=send_teardown_cb)
        self._update_key_requested = False

    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int]:
        plain_header, payload, packet_number, update_key = self.recv.decrypt_packet(
            packet, encrypted_offset, expected_packet_number
        )
        if update_key:
            self._update_key("remote_update")
        return plain_header, payload, packet_number

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        if self._update_key_requested:
            self._update_key("local_update")
        return self.send.encrypt_packet(plain_header, plain_payload, packet_number)

    def setup_initial(self, cid: bytes, is_client: bool, version: int) -> None:
        if is_client:
            recv_label, send_label = b"server in", b"client in"
        else:
            recv_label, send_label = b"client in", b"server in"

        if version == QuicProtocolVersion.VERSION_2:
            initial_salt = INITIAL_SALT_VERSION_2
        else:
            initial_salt = INITIAL_SALT_VERSION_1

        algorithm = cipher_suite_hash(INITIAL_CIPHER_SUITE)
        digest_size = int(algorithm / 8)
        initial_secret = hkdf_extract(algorithm, initial_salt, cid)
        self.recv.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, recv_label, b"", digest_size
            ),
            version=version,
        )
        self.send.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, send_label, b"", digest_size
            ),
            version=version,
        )

    def teardown(self) -> None:
        self.recv.teardown()
        self.send.teardown()

    def update_key(self) -> None:
        self._update_key_requested = True

    @property
    def key_phase(self) -> int:
        if self._update_key_requested:
            return int(not self.recv.key_phase)
        else:
            return self.recv.key_phase

    def _update_key(self, trigger: str) -> None:
        apply_key_phase(self.recv, next_key_phase(self.recv), trigger=trigger)
        apply_key_phase(self.send, next_key_phase(self.send), trigger=trigger)
        self._update_key_requested = False
