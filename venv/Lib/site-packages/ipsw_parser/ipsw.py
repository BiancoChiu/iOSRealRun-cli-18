import logging
import plistlib
import zipfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from cached_property import cached_property
from construct import Const, Default, PaddedString, Struct

from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.firmware import Firmware

logger = logging.getLogger(__name__)

cpio_odc_header = Struct(
    'c_magic' / Const('070707', PaddedString(6, 'utf8')),
    'c_dev' / Default(PaddedString(6, 'utf8'), '0' * 6, ),
    'c_ino' / PaddedString(6, 'utf8'),
    'c_mode' / PaddedString(6, 'utf8'),
    'c_uid' / Default(PaddedString(6, 'utf8'), '0' * 6),
    'c_gid' / Default(PaddedString(6, 'utf8'), '0' * 6),
    'c_nlink' / PaddedString(6, 'utf8'),
    'c_rdev' / Default(PaddedString(6, 'utf8'), '0' * 6),
    'c_mtime' / Default(PaddedString(11, 'utf8'), '0' * 11),
    'c_namesize' / PaddedString(6, 'utf8'),
    'c_filesize' / Default(PaddedString(11, 'utf8'), '0' * 11),
)


class IPSW:
    def __init__(self, archive: zipfile.ZipFile):
        self.archive = archive
        self._logger = logging.getLogger(__file__)
        self.build_manifest = BuildManifest(self, self.archive.read(
            next(f for f in self.archive.namelist() if f.startswith('BuildManifest') and f.endswith('.plist'))))

    @cached_property
    def restore_version(self) -> bytes:
        return self.read('RestoreVersion.plist')

    @cached_property
    def system_version(self) -> bytes:
        return self.read('SystemVersion.plist')

    @cached_property
    def filelist(self) -> list[zipfile.ZipInfo]:
        return self.archive.filelist

    @contextmanager
    def open_path(self, path: str):
        file = self.archive.open(path)
        try:
            yield file
        finally:
            file.close()

    @property
    def bootability(self) -> bytes:
        result = b''
        prefix = 'BootabilityBundle/Restore/Bootability/'
        inode = 1
        nlink = 1

        for e in self.filelist:
            if e.filename == 'BootabilityBundle/Restore/Firmware/Bootability.dmg.trustcache':
                subpath = 'Bootability.trustcache'
            elif not e.filename.startswith(prefix):
                continue
            else:
                subpath = e.filename[len(prefix):]

            self._logger.debug(f'BootabilityBundle: adding {subpath}')

            filename = subpath
            filename = f'{filename}\0'.encode()
            mode = e.external_attr >> 16
            result += cpio_odc_header.build({
                'c_ino': f'{inode:06o}', 'c_nlink': f'{nlink:06o}', 'c_mode': f'{mode:06o}',
                'c_namesize': f'{len(filename):06o}', 'c_filesize': f'{e.file_size:011o}'})
            inode += 1
            result += filename
            if not e.file_size:
                continue

            with self.open_path(e.filename) as f:
                result += f.read()

        filename = b'TRAILER!!!\0'
        inode = 0
        mode = 0
        result += cpio_odc_header.build(
            {'c_ino': f'{inode:06o}', 'c_mode': f'{mode:06o}', 'c_nlink': f'{nlink:06o}',
             'c_namesize': f'{len(filename):06o}'}) + filename
        return result

    def read(self, path: str) -> bytes:
        return self.archive.read(path)

    def get_global_manifest(self, macos_variant: str, device_class: str) -> bytes:
        manifest_path = f'Firmware/Manifests/restore/{macos_variant}/apticket.{device_class}.im4m'
        return self.read(manifest_path)

    def get_firmware(self, firmware_path: str) -> Firmware:
        return Firmware(firmware_path, self)

    def get_development_files(self) -> list[str]:
        result = []
        for entry in self.archive.namelist():
            for release in ('devel', 'kasan', 'research'):
                if release in entry.lower():
                    result.append(entry)
        return result

    def create_device_support(self, pem_db: Optional[str] = None) -> None:
        device_support_path = Path('~/Library/Developer/Xcode/iOS DeviceSupport').expanduser()
        device_support_path /= (f'{self.build_manifest.supported_product_types[0]} '
                                f'{self.build_manifest.product_version} ({self.build_manifest.product_build_version})')
        build_identity = self.build_manifest.build_identities[0]
        symbols_path = device_support_path / 'Symbols'
        build_identity.extract_dsc(symbols_path, pem_db=pem_db)
        for file in (symbols_path / 'private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld').iterdir():
            file.unlink()
        (device_support_path / 'Info.plist').write_bytes(plistlib.dumps({
            'DSC Extractor Version': '1228.0.0.0.0',
            'DateCollected': datetime.now(),
            'Version': '16.0',
        }))
        (device_support_path / '.finalized').write_bytes(plistlib.dumps({}))
        (device_support_path / '.processed_dyld_shared_cache_arm64e').touch()
        (device_support_path / '.processing_lock').touch()
