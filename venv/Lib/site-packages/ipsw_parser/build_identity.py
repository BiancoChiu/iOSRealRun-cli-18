import logging
import os
import shutil
from collections import UserDict
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional
from zipfile import ZipFile

import requests
from cached_property import cached_property
from plumbum import ProcessExecutionError, local
from pyimg4 import IM4P

from ipsw_parser.component import Component

logger = logging.getLogger(__name__)

AEA_MAGIC = b'AEA1'


def extract_as(zipf: ZipFile, member_name, output_path, chunk_size=64 * 1024):
    """Extract a single member from a ZIP archive to a custom output path"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with zipf.open(member_name) as source, open(output_path, 'wb') as target:
        shutil.copyfileobj(source, target, length=chunk_size)


def _extract_dmg(dmg: Path, output: Path, sub_path: Optional[Path] = None, pem_db: Optional[str] = None) -> None:
    ipsw = local['ipsw']
    hdiutil = local['hdiutil']
    # darwin system statistically have problems cleaning up after detaching the mountpoint
    with TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        mnt = temp_dir / 'mnt'
        mnt.mkdir()

        with dmg.open('rb') as f:
            magic = f.read(len(AEA_MAGIC))
        if magic == AEA_MAGIC:
            logger.debug('Found Apple Encrypted Archive. Decrypting...')
            aea_dmg = str(dmg.absolute()) + '.aea'
            dmg.rename(aea_dmg)
            dmg = temp_dir / Path(aea_dmg).name.rsplit('.', 1)[0]
            args = ['fw', 'aea', aea_dmg, '-o', temp_dir]
            if pem_db is not None:
                if '://' in pem_db:
                    # create a local file containing it
                    temp_pem_db = temp_dir / 'pem-db.json'
                    temp_pem_db.write_text(requests.get(pem_db, verify=False).text)
                    pem_db = temp_pem_db
                args += ['--pem-db', pem_db]
            ipsw(args)

        hdiutil('attach', '-mountpoint', mnt, dmg)

        try:
            if sub_path is None:
                src = mnt
            else:
                src = mnt / sub_path
            shutil.copytree(src, output, symlinks=True, dirs_exist_ok=True)
        except shutil.Error:
            # when overwriting the same files, some of them don't contain write permissions
            pass

        hdiutil('detach', '-force', mnt)


def _split_dsc(root: Path) -> None:
    ipsw = local['ipsw']
    dsc_paths = [
        root / 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64',
        root / 'System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e',
        root / 'private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64',
        root / 'private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e']

    for dsc in dsc_paths:
        if not dsc.exists():
            continue

        logger.info(f'splitting DSC: {dsc}')
        ipsw('dyld', 'split', dsc, '-o', root)


class BuildIdentity(UserDict):
    def __init__(self, build_manifest, data):
        super().__init__(data)
        self.build_manifest = build_manifest

    @cached_property
    def device_class(self) -> str:
        return self['Info']['DeviceClass'].lower()

    @cached_property
    def restore_behavior(self) -> str:
        return self['Info'].get('RestoreBehavior')

    @cached_property
    def variant(self):
        return self['Info'].get('Variant')

    @cached_property
    def macos_variant(self) -> str:
        return self['Info'].get('MacOSVariant')

    @cached_property
    def manifest(self) -> dict:
        return self['Manifest']

    @cached_property
    def minimum_system_partition(self):
        return self['Info'].get('MinimumSystemPartition')

    def get_component_path(self, component: str) -> str:
        return self.manifest[component]['Info']['Path']

    def has_component(self, name: str) -> bool:
        return name in self.manifest

    def get_component(self, name: str, **args) -> Component:
        return Component(self, name, **args)

    def extract_dsc(self, output: Path, pem_db: Optional[str] = None) -> None:
        build_identity = self.build_manifest.build_identities[0]
        if not build_identity.has_component('Cryptex1,SystemOS'):
            return

        device_support_symbols_path = output / 'private/preboot/Cryptexes/OS/System'
        device_support_symbols_path.mkdir(parents=True, exist_ok=True)

        with TemporaryDirectory() as temp_dir:
            system_os = Path(temp_dir) / 'system_os.dmg'
            system_os_component_path = build_identity.get_component_path('Cryptex1,SystemOS')
            extract_as(self.build_manifest.ipsw.archive, system_os_component_path, system_os)
            _extract_dmg(system_os, device_support_symbols_path,
                         sub_path=Path('System'), pem_db=pem_db)
        _split_dsc(output)

    def get_kernelcache_payload(self, arch: Optional[str] = None) -> bytes:
        im4p = IM4P(self.build_manifest.build_identities[0].get_component('KernelCache').data)
        im4p.payload.decompress()
        payload = im4p.payload.output().data
        if arch is None:
            return payload

        with TemporaryDirectory() as temp_dir:
            kernel_output = Path(temp_dir) / 'kernel'
            local['ipsw']('macho', 'lipo', '-a', arch, kernel_output)
            return Path(next(kernel_output.parent.glob(f'*.{arch}'))).read_bytes()

    def extract(self, output: Path, pem_db: Optional[str] = None) -> None:
        logger.info(f'extracting into: {output}')

        build_identity = self.build_manifest.build_identities[0]

        logger.info(f'extracting OS into: {output}')
        with TemporaryDirectory() as temp_dir:
            os_dmg = Path(temp_dir) / 'os.dmg'
            os_component_path = build_identity.get_component_path('OS')
            extract_as(self.build_manifest.ipsw.archive, os_component_path, os_dmg)
            _extract_dmg(os_dmg, output, pem_db=pem_db)

        kernel_component = build_identity.get_component('KernelCache')
        kernel_path = Path(kernel_component.path)
        kernel_output = output / 'System/Library/Caches/com.apple.kernelcaches' / kernel_path.parts[-1]
        kernel_output.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f'extracting kernel into: {kernel_output}')
        im4p = IM4P(kernel_component.data)
        im4p.payload.decompress()
        kernel_output.write_bytes(im4p.payload.output().data)
        try:
            # In case the kernel is a FAT image, extract the arm64 macho
            local['ipsw']('macho', 'lipo', '-a', 'arm64', kernel_output)
            list(kernel_output.parent.glob('*.arm64'))[0].rename(kernel_output)
        except ProcessExecutionError:
            pass

        for cryptex in ('App', 'OS'):
            name = {
                'App': 'Cryptex1,AppOS',
                'OS': 'Cryptex1,SystemOS',
            }[cryptex]

            if not build_identity.has_component(name):
                continue

            cryptex_path = output / 'private/preboot/Cryptexes' / cryptex
            cryptex_path.mkdir(parents=True, exist_ok=True)

            logger.info(f'extracting {name} into: {cryptex_path}')
            with TemporaryDirectory() as temp_dir:
                temp_component = (Path(temp_dir) / name).with_suffix('.dmg')
                component_path = build_identity.get_component_path(name)
                extract_as(self.build_manifest.ipsw.archive, component_path, temp_component)
                _extract_dmg(temp_component, cryptex_path, pem_db=pem_db)

        _split_dsc(output)
