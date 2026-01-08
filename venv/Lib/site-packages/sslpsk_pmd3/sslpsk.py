# Copyright 2017 David R. Bild
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

from __future__ import absolute_import

import ssl
import weakref

import _ssl

if ssl.OPENSSL_VERSION_INFO >= (3, 0):
    from sslpsk_pmd3 import _sslpsk_openssl3 as _sslpsk
else:
    from sslpsk_pmd3 import _sslpsk_openssl1 as _sslpsk


_callbacks = {}


class FinalizerRef(weakref.ref):
    """subclass weakref.ref so that attributes can be added"""


def _register_callback(sock, ssl_id, callback):
    _callbacks[ssl_id] = callback
    callback.unregister = FinalizerRef(sock, _unregister_callback)
    callback.unregister.ssl_id = ssl_id


def _unregister_callback(ref):
    del _callbacks[ref.ssl_id]


def _python_psk_client_callback(ssl_id, hint):
    """Called by _sslpsk.c to return the (psk, identity) tuple for the socket with
    the specified ssl socket.

    """
    if ssl_id not in _callbacks:
        return (b"", b"")
    else:
        res = _callbacks[ssl_id](hint)
        return res if isinstance(res, tuple) else (res, b"")


def _sslobj(sock):
    """Returns the underlying PySLLSocket object with which the C extension
    functions interface.

    """
    if isinstance(sock._sslobj, _ssl._SSLSocket):
        return sock._sslobj
    else:
        return sock._sslobj._sslobj


def _python_psk_server_callback(ssl_id, identity):
    """Called by _sslpsk.c to return the psk for the socket with the specified
    ssl socket.

    """
    if ssl_id not in _callbacks:
        return b""
    else:
        return _callbacks[ssl_id](identity)


_sslpsk.sslpsk_set_python_psk_client_callback(_python_psk_client_callback)
_sslpsk.sslpsk_set_python_psk_server_callback(_python_psk_server_callback)


def _ssl_set_psk_client_callback(sock, psk_cb):
    ssl_id = _sslpsk.sslpsk_set_psk_client_callback(_sslobj(sock))
    _register_callback(sock, ssl_id, psk_cb)


def _ssl_set_psk_server_callback(sock, psk_cb, hint):
    ssl_id = _sslpsk.sslpsk_set_accept_state(_sslobj(sock))
    _ = _sslpsk.sslpsk_set_psk_server_callback(_sslobj(sock))
    _ = _sslpsk.sslpsk_use_psk_identity_hint(_sslobj(sock), hint if hint else b"")
    _register_callback(sock, ssl_id, psk_cb)

def _ssl_setup_psk_callbacks(sslobj):
    psk = sslobj.context.psk
    hint = sslobj.context.hint
    if psk:
        if sslobj.server_side:
            cb = psk if callable(psk) else lambda _identity: psk
            _ssl_set_psk_server_callback(sslobj, cb, hint)
        else:
            cb = psk if callable(psk) else lambda _hint: psk if isinstance(psk, tuple) else (psk, b"")
            _ssl_set_psk_client_callback(sslobj, cb)


class SSLPSKContext(ssl.SSLContext):
    @property
    def psk(self):
        return getattr(self, "_psk", None)

    @psk.setter
    def psk(self, psk):
        self._psk = psk

    @property
    def hint(self):
        return getattr(self, "_hint", None)

    @hint.setter
    def hint(self, hint):
        self._hint = hint


class SSLPSKObject(ssl.SSLObject):
    def do_handshake(self, *args, **kwargs):
        _ssl_setup_psk_callbacks(self)
        super().do_handshake(*args, **kwargs)


class SSLPSKSocket(ssl.SSLSocket):
    def do_handshake(self, *args, **kwargs):
        _ssl_setup_psk_callbacks(self)
        super().do_handshake(*args, **kwargs)


SSLPSKContext.sslobject_class = SSLPSKObject
SSLPSKContext.sslsocket_class = SSLPSKSocket

def wrap_socket(*args, **kwargs):
    """ """
    do_handshake_on_connect = kwargs.get("do_handshake_on_connect", True)
    kwargs["do_handshake_on_connect"] = False

    psk = kwargs.setdefault("psk", None)
    del kwargs["psk"]

    hint = kwargs.setdefault("hint", None)
    del kwargs["hint"]

    server_side = kwargs.setdefault("server_side", False)
    if psk:
        del kwargs["server_side"]  # bypass need for cert

    sock = ssl.wrap_socket(*args, **kwargs)

    if psk:
        if server_side:
            cb = psk if callable(psk) else lambda _identity: psk
            _ssl_set_psk_server_callback(sock, cb, hint)
        else:
            cb = (
                psk
                if callable(psk)
                else lambda _hint: psk
                if isinstance(psk, tuple)
                else (psk, b"")
            )
            _ssl_set_psk_client_callback(sock, cb)

    if do_handshake_on_connect:
        sock.do_handshake()

    return sock
