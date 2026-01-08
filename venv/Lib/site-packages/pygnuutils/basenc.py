import base64 as b64
import struct
import sys
from dataclasses import dataclass
from enum import Enum, auto
from itertools import zip_longest

from pygnuutils.exceptions import BasencDecodeError

BASE64_VALID = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
BASE64_URL_VALID = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
BASE32_VALID = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
BASE32_HEX_VALID = b'0123456789ABCDEFGHIJKLMNOPQRSTUV'
BASE16_VALID = b'0123456789ABCDEF'
BASE2_VALID = b'01'
Z85_VALID = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'

BASE64_URL_DECODE_TRANSLATION = bytes.maketrans(b'-_', b'+/')
BASE32_HEX_ENCODE_TRANSLATION = bytes.maketrans(BASE32_VALID, BASE32_HEX_VALID)
BASE32_HEX_DECODE_TRANSLATION = bytes.maketrans(BASE32_HEX_VALID, BASE32_VALID)

Z85_ENCODE_TRANSLATION = bytes.maketrans(
    b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~', Z85_VALID
)

Z85_DECODE_TRANSLATION = bytes.maketrans(
    Z85_VALID, b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
)


def grouper(iterable, n, fillvalue=None):
    """ Collect data into non-overlapping fixed-length chunks or blocks. """
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def b32hex_encode(s):
    if sys.version_info >= (3, 10):
        return b64.b32hexencode(s)
    return b64.b32encode(s).translate(BASE32_HEX_ENCODE_TRANSLATION)


def base2_msbf_encode(s):
    return b''.join([f'{c:08b}'.encode() for c in s])


def base2_lsbf_encode(s):
    return b''.join([f'{c:08b}'[::-1].encode() for c in s])


def z85_encode(s):
    return b64.b85encode(s).translate(Z85_ENCODE_TRANSLATION)


def base64_url_decode(s):
    s = s.translate(BASE64_URL_DECODE_TRANSLATION)
    return b64.b64decode(s, validate=True)


def b32hex_decode(s):
    if sys.version_info >= (3, 10):
        return b64.b32hexdecode(s)
    return b64.b32decode(s.translate(BASE32_HEX_DECODE_TRANSLATION))


def base2_msbf_decode(s):
    return bytes(map(lambda b: int(struct.pack('8B', *b), 2), grouper(s, 8)))


def base2_lsbf_decode(s):
    return bytes(map(lambda b: int(struct.pack('8B', *b)[::-1], 2), grouper(s, 8)))


def z85_decode(s):
    return b64.b85decode(s.translate(Z85_DECODE_TRANSLATION))


class Encoding(Enum):
    BASE64 = auto()
    BASE64_URL = auto()
    BASE32 = auto()
    BASE32_HEX = auto()
    BASE16 = auto()
    BASE2_MSBF = auto()
    BASE2_LSBF = auto()
    Z85 = auto()


class BasencStub:
    @property
    def stdin_buffer(self):
        return sys.stdin.buffer

    @property
    def stdout_buffer(self):
        return sys.stdout.buffer

    def open(self, file, mode):
        return open(file, mode)

    def close(self, fd):
        fd.close()


@dataclass
class BasencConfig:
    encoding: Encoding = Encoding.BASE64
    decode: bool = False
    ignore_garbage: bool = False
    wrap_column: int = 76


class Basenc:
    DEC_BLOCKSIZE = 4200
    ENC_BLOCKSIZE = 1024 * 3 * 10

    def __init__(self, stub=None):
        self.stub = BasencStub() if stub is None else stub
        self.config = BasencConfig()
        self.base_encodes = {
            Encoding.BASE64: b64.standard_b64encode,
            Encoding.BASE64_URL: b64.urlsafe_b64encode,
            Encoding.BASE32: b64.b32encode,
            Encoding.BASE32_HEX: b32hex_encode,
            Encoding.BASE16: b64.b16encode,
            Encoding.BASE2_MSBF: base2_msbf_encode,
            Encoding.BASE2_LSBF: base2_lsbf_encode,
            Encoding.Z85: z85_encode,
        }
        self.is_bases = {
            Encoding.BASE64: lambda char: char in BASE64_VALID,
            Encoding.BASE64_URL: lambda char: char in BASE64_URL_VALID,
            Encoding.BASE32: lambda char: char in BASE32_VALID,
            Encoding.BASE32_HEX: lambda char: char in BASE32_HEX_VALID,
            Encoding.BASE16: lambda char: char in BASE16_VALID,
            Encoding.BASE2_MSBF: lambda char: char in BASE2_VALID,
            Encoding.BASE2_LSBF: lambda char: char in BASE2_VALID,
            Encoding.Z85: lambda char: char in Z85_VALID,
        }
        self.base_decodes = {
            Encoding.BASE64: lambda s: b64.b64decode(s, validate=True),
            Encoding.BASE64_URL: base64_url_decode,
            Encoding.BASE32: b64.b32decode,
            Encoding.BASE32_HEX: b32hex_decode,
            Encoding.BASE16: b64.b16decode,
            Encoding.BASE2_MSBF: base2_msbf_decode,
            Encoding.BASE2_LSBF: base2_lsbf_decode,
            Encoding.Z85: z85_decode,
        }

    def run(self, file, config=None):
        if config is not None:
            self.config = config
        if file == '-':
            input_fd = self.stub.stdin_buffer
        else:
            input_fd = self.stub.open(file, 'rb')

        if self.config.decode:
            self._do_decode(input_fd)
        else:
            self._do_encode(input_fd)

        if file != '-':
            self.stub.close(input_fd)

    def _do_decode(self, input_fd):
        while True:
            prev_in_buf_len = 0
            in_buf = input_fd.read(self.DEC_BLOCKSIZE)
            if self.config.ignore_garbage:
                in_buf = bytes([b for b in in_buf if chr(b) == '=' or self._is_base(b.to_bytes(1, 'big'))])
            while len(in_buf) != prev_in_buf_len and len(in_buf) != self.DEC_BLOCKSIZE:
                prev_in_buf_len = len(in_buf)
                in_buf += input_fd.read(self.DEC_BLOCKSIZE - prev_in_buf_len)

            try:
                self.stub.stdout_buffer.write(self._base_decode(in_buf))
            except (ValueError, struct.error) as e:
                raise BasencDecodeError from e

            if len(in_buf) != self.DEC_BLOCKSIZE:
                break

    def _do_encode(self, input_fd):
        current_column = 0
        while True:
            prev_in_buf_len = 0
            in_buf = input_fd.read(self.ENC_BLOCKSIZE)
            while len(in_buf) != prev_in_buf_len and len(in_buf) != self.ENC_BLOCKSIZE:
                prev_in_buf_len = len(in_buf)
                in_buf += input_fd.read(self.ENC_BLOCKSIZE - prev_in_buf_len)
            current_column = self._wrap_write(self._base_encode(in_buf), current_column)
            if len(in_buf) != self.ENC_BLOCKSIZE:
                break

        if self.config.wrap_column and current_column:
            self.stub.stdout_buffer.write(b'\n')

    def _base_encode(self, in_buf):
        return self.base_encodes[self.config.encoding](in_buf)

    def _is_base(self, char):
        return self.is_bases[self.config.encoding](char)

    def _base_decode(self, in_buf):
        return self.base_decodes[self.config.encoding](in_buf)

    def _wrap_write(self, buffer, current_column):
        if not self.config.wrap_column:
            self.stub.stdout_buffer.write(buffer)
            return 0

        if current_column:
            self.stub.stdout_buffer.write(buffer[:self.config.wrap_column - current_column])
            self.stub.stdout_buffer.write(b'\n')
            buffer = buffer[self.config.wrap_column - current_column:]

        i = 0
        for i in range(0, len(buffer), self.config.wrap_column):
            if i + self.config.wrap_column > len(buffer):
                break
            self.stub.stdout_buffer.write(buffer[i:i + self.config.wrap_column])
            self.stub.stdout_buffer.write(b'\n')
        if i < len(buffer):
            self.stub.stdout_buffer.write(buffer[i:])
            return len(buffer) % self.config.wrap_column
        return 0

    def __call__(self, file='-', base64=False, base64url=False, base32=False, base32hex=False, base16=False,
                 base2msbf=False, base2lsbf=False, decode=False, ignore_garbage=False, wrap=76, z85=False):
        encoding = Encoding.BASE64
        if base64url:
            encoding = Encoding.BASE64_URL
        if base32:
            encoding = Encoding.BASE32
        if base32hex:
            encoding = Encoding.BASE32_HEX
        if base16:
            encoding = Encoding.BASE16
        if base2msbf:
            encoding = Encoding.BASE2_MSBF
        if base2lsbf:
            encoding = Encoding.BASE2_LSBF
        if z85:
            encoding = Encoding.Z85
        config = BasencConfig(
            encoding=encoding,
            decode=decode,
            ignore_garbage=ignore_garbage,
            wrap_column=wrap,
        )
        self.run(file, config)
