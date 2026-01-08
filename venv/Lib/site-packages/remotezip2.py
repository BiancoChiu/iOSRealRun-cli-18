#!/usr/bin/env python
import io
import zipfile
from datetime import datetime
from itertools import tee

import requests

__all__ = ['RemoteIOError', 'RemoteZip']


class RemoteZipError(Exception):
    pass


class OutOfBound(RemoteZipError):
    pass


class RemoteIOError(RemoteZipError):
    pass


class RangeNotSupported(RemoteZipError):
    pass


class PartialBuffer:
    """An object with buffer-like interface but containing just a part of the data.
        The object allows to seek and read like this buffer contains the full data
        however, any attempt to read data outside the partial data is going to fail
        with OutOfBound error.
    """

    def __init__(self, buffer, offset, size, stream):
        self.buffer = buffer if stream else io.BytesIO(buffer.read())
        self._offset = offset
        self._size = size
        self._position = offset
        self._stream = stream

    def __len__(self):
        """Returns the data size contained in the buffer"""
        return self._size

    def __repr__(self):
        return "<PartialBuffer off=%s size=%s stream=%s>" % (self._offset, self._size, self._stream)

    def read(self, size=0):
        """Read data from the buffer from the current position"""
        if size == 0:
            size = self._offset + self._size - self._position

        content = self.buffer.read(size)
        self._position = self._offset + self.buffer.tell()
        return content

    def close(self):
        """Ensure memory and connections are closed"""
        if not self.buffer.closed:
            self.buffer.close()
            if hasattr(self.buffer, 'release_conn'):
                self.buffer.release_conn()

    def tell(self):
        """Returns the current position on the virtual buffer"""
        return self._position

    def seek(self, offset, whence):
        """Change the position on the virtual buffer"""
        if whence == 2:
            self._position = self._size + self._offset + offset
        elif whence == 0:
            self._position = offset
        else:
            self._position += offset

        relative_position = self._position - self._offset

        if relative_position < 0 or relative_position >= self._size:
            raise OutOfBound("Position out of buffer bound")

        if self._stream:
            buff_pos = self.buffer.tell()
            if relative_position < buff_pos:
                raise OutOfBound("Negative seek not supported")

            skip_bytes = relative_position - buff_pos
            if skip_bytes == 0:
                return self._position
            self.buffer.read(skip_bytes)
        else:
            self.buffer.seek(relative_position)

        return self._position


class RemoteIO(io.IOBase):
    """Exposes a file-like interface for zip files hosted remotely. It requires the remote server to
    support the Range header."""

    def __init__(self, fetch_fun, initial_buffer_size=64 * 1024):
        self._fetch_fun = fetch_fun
        self._initial_buffer_size = initial_buffer_size
        self.buffer = None
        self._file_size = None
        self._seek_succeeded = False
        self._member_position_to_size = None
        self._last_member_pos = None

    def set_position_to_size(self, position_to_size):
        self._member_position_to_size = position_to_size

    def read(self, size=0):
        position = self.tell()
        if size == 0:
            size = self._file_size - position

        if not self._seek_succeeded:
            if self._member_position_to_size is None:
                fetch_size = size
                stream = False
            else:
                try:
                    fetch_size = self._member_position_to_size[position]
                    self._last_member_pos = position
                except KeyError:
                    if self._last_member_pos and self._last_member_pos < position:
                        fetch_size = self._member_position_to_size[self._last_member_pos]
                        fetch_size -= (position - self._last_member_pos)
                    else:
                        raise OutOfBound("Attempt to seek outside boundary of current zip member")
                stream = True

            self._seek_succeeded = True
            self.buffer.close()
            self.buffer = self._fetch_fun((position, position + fetch_size - 1), stream=stream)

        return self.buffer.read(size)

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        if whence == 2 and self._file_size is None:
            size = self._initial_buffer_size
            self.buffer = self._fetch_fun((-size, None), stream=False)
            self._file_size = len(self.buffer) + self.buffer.tell()

        try:
            pos = self.buffer.seek(offset, whence)
            self._seek_succeeded = True
            return pos
        except OutOfBound:
            self._seek_succeeded = False
            return self.tell()  # we ignore the issue here, we will check if buffer is fine during read

    def tell(self):
        return self.buffer.tell()

    def close(self):
        if self.buffer:
            self.buffer.close()
            self.buffer = None


class RemoteFetcher:
    """Represent a remote file to be fetched in parts"""

    def __init__(self, url, session=None, support_suffix_range=True, **kwargs):
        self._kwargs = kwargs
        self._url = url
        self._session = session
        self._support_suffix_range = support_suffix_range

    @staticmethod
    def parse_range_header(content_range_header):
        range = content_range_header[6:].split("/")[0]
        if range.startswith("-"):
            return int(range), None
        range_min, range_max = range.split("-")
        return int(range_min), int(range_max) if range_max else None

    @staticmethod
    def build_range_header(range_min, range_max):
        if range_max is None:
            return "bytes=%s%s" % (range_min, '' if range_min < 0 else '-')
        return "bytes=%s-%s" % (range_min, range_max)

    def _request(self, kwargs):
        if self._session:
            res = self._session.get(self._url, stream=True, **kwargs)
        else:
            res = requests.get(self._url, stream=True, **kwargs)
        res.raise_for_status()
        if 'Content-Range' not in res.headers:
            raise RangeNotSupported("The server doesn't support range requests")
        buffer = res.raw
        if hasattr(buffer, 'decode_content'):
            # Special case for urllib3
            buffer.decode_content = True
        return buffer, res.headers['Content-Range']

    def prepare_request(self, data_range=None):
        kwargs = dict(self._kwargs)
        kwargs['headers'] = headers = dict(kwargs.get('headers', {}))
        if data_range is not None:
            headers['Range'] = self.build_range_header(*data_range)
        return kwargs

    def get_file_size(self):
        if self._session:
            res = self._session.head(self._url, **self.prepare_request())
        else:
            res = requests.head(self._url, **self.prepare_request())
        try:
            res.raise_for_status()
            return int(res.headers['Content-Length'])
        except IOError as e:
            raise RemoteIOError(str(e))
        except KeyError:
            raise RemoteZipError("Cannot get file size: Content-Length header missing")

    def fetch(self, data_range, stream=False):
        """Fetch a part of a remote file"""
        # Handle the case suffix range request is not supported. Fixes #15
        if data_range[0] < 0 and data_range[1] is None and not self._support_suffix_range:
            size = self.get_file_size()
            data_range = (max(0, size + data_range[0]), size - 1)

        kwargs = self.prepare_request(data_range)
        try:
            res, range_header = self._request(kwargs)
            range_min, range_max = self.parse_range_header(range_header)
            return PartialBuffer(res, range_min, range_max - range_min + 1, stream)
        except IOError as e:
            raise RemoteIOError(str(e))


def pairwise(iterable):
    # pairwise('ABCDEFG') --> AB BC CD DE EF FG
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


class RemoteZip(zipfile.ZipFile):
    def __init__(self, url, initial_buffer_size=64 * 1024, session=None, fetcher=RemoteFetcher,
                 support_suffix_range=True,
                 **kwargs):
        fetcher = fetcher(url, session, support_suffix_range=support_suffix_range, **kwargs)
        rio = RemoteIO(fetcher.fetch, initial_buffer_size)
        super(RemoteZip, self).__init__(rio)

    def size(self):
        return self.fp._file_size if self.fp else 0


def _list_files(url, support_suffix_range, filenames):
    with RemoteZip(url, headers={'User-Agent': 'remotezip'}, support_suffix_range=support_suffix_range) as zip:
        if len(filenames) == 0:
            filenames = zip.namelist()
        data = []
        for fname in filenames:
            zinfo = zip.getinfo(fname)
            dt = datetime(*zinfo.date_time)
            data.append((zinfo.file_size, dt.strftime('%Y-%m-%d %H:%M:%S'), zinfo.filename))
        _printTable(data, ('Length', 'DateTime', 'Name'), '><<')


def _printTable(data, header, align):
    # get max col width & prepare formatting string
    col_w = [len(col) for col in header]
    for row in data:
        col_w = [max(w, len(str(x))) for w, x in zip(col_w, row)]
    fmt = '  '.join('{{:{}{}}}'.format(a, w)
                    for w, a in zip(col_w, align + '<' * 99))
    # print table
    print(fmt.format(*header).rstrip())
    print(fmt.format(*['-' * w for w in col_w]))
    for row in data:
        print(fmt.format(*row).rstrip())
    print()


def _extract_files(url, support_suffix_range, filenames, path):
    with RemoteZip(url, support_suffix_range=support_suffix_range) as zip:
        if len(filenames) == 0:
            filenames = zip.namelist()
        for fname in filenames:
            print('Extracting {0}...'.format(fname))
            zip.extract(fname, path=path)


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Unzip remote files")
    parser.add_argument('url', help='URL of the zip archive')
    parser.add_argument('filename', nargs='*', help='File to extract')
    parser.add_argument('-l', '--list', action='store_true', help='List files in the archive')
    parser.add_argument('-d', '--dir', default=os.getcwd(), help='Extract directory, default current directory')
    parser.add_argument('--disable-suffix-range-support', action='store_true',
                        help='Use when remote server does not support suffix range (negative offset)')

    args = parser.parse_args()
    support_suffix_range = not args.disable_suffix_range_support
    if args.list:
        _list_files(args.url, support_suffix_range, args.filename)
    else:
        _extract_files(args.url, support_suffix_range, args.filename, args.dir)


if __name__ == "__main__":
    main()
