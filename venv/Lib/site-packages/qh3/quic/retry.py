from __future__ import annotations

import ipaddress

from .._hazmat import Buffer, Rsa
from ..tls import pull_opaque, push_opaque
from .connection import NetworkAddress


def encode_address(addr: NetworkAddress) -> bytes:
    return ipaddress.ip_address(addr[0]).packed + bytes([addr[1] >> 8, addr[1] & 0xFF])


class QuicRetryTokenHandler:
    def __init__(self) -> None:
        self._key = Rsa(key_size=2048)

    def create_token(
        self,
        addr: NetworkAddress,
        original_destination_connection_id: bytes,
        retry_source_connection_id: bytes,
    ) -> bytes:
        buf = Buffer(capacity=512)
        push_opaque(buf, 1, encode_address(addr))
        push_opaque(buf, 1, original_destination_connection_id)
        push_opaque(buf, 1, retry_source_connection_id)
        return self._key.encrypt(buf.data)

    def validate_token(self, addr: NetworkAddress, token: bytes) -> tuple[bytes, bytes]:
        if not token or len(token) != 256:
            raise ValueError("Ciphertext length must be equal to key size.")
        buf = Buffer(data=self._key.decrypt(token))
        encoded_addr = pull_opaque(buf, 1)
        original_destination_connection_id = pull_opaque(buf, 1)
        retry_source_connection_id = pull_opaque(buf, 1)
        if encoded_addr != encode_address(addr):
            raise ValueError("Remote address does not match.")
        return original_destination_connection_id, retry_source_connection_id
