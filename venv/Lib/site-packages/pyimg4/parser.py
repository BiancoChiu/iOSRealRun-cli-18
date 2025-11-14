from os import getenv
from sys import platform
from typing import Any, List, Optional, Tuple, Union
from zlib import adler32

import asn1
import lzss
from Crypto.Cipher import AES

from .errors import CompressionError, UnexpectedDataError, UnexpectedTagError
from .types import Compression, KeybagType, Payload

FORCE_LZFSE = getenv('PYIMG4_FORCE_LZFSE', None) is not None

if platform != 'darwin' or FORCE_LZFSE is True:
    import lzfse

    def _lzfse_compress(data: bytes) -> bytes:
        return lzfse.compress(data)

    def _lzfse_decompress(data: bytes, _: Optional[int] = None) -> bytes:
        return lzfse.decompress(data)

else:
    import apple_compress

    def _lzfse_compress(data: bytes) -> bytes:
        return apple_compress.compress(
            data, algorithm=apple_compress.Algorithm.LZFSE_IBOOT
        )

    def _lzfse_decompress(data: bytes, decmp_size: Optional[int] = None) -> bytes:
        return apple_compress.decompress(
            data,
            algorithm=apple_compress.Algorithm.LZFSE_IBOOT,
            decmp_size=decmp_size,
        )


class _PyIMG4:
    def __init__(self, data: Optional[bytes] = None) -> None:
        self._data = data

        self._decoder = asn1.Decoder()
        self._encoder = asn1.Encoder()

    def __bytes__(self) -> bytes:
        return self.output()

    def __eq__(self, obj: Any) -> bool:
        if isinstance(obj, _PyIMG4):
            return self.output() == obj.output()
        elif isinstance(obj, bytes):
            return self.output() == obj
        else:
            return False

    def __len__(self) -> int:
        return len(self.output())

    def _verify_fourcc(self, fourcc: str, correct: str = None) -> str:
        if not isinstance(fourcc, str):
            raise UnexpectedDataError('string', fourcc)

        if correct is not None:
            self._verify_fourcc(correct)

            if fourcc.casefold() == correct.casefold():
                return fourcc
            else:
                raise UnexpectedDataError(correct, fourcc)

        if len(fourcc) != 4:
            raise UnexpectedDataError('string with length of 4', fourcc)

        return fourcc

    def output(self) -> bytes:
        return self._data


class _Property(_PyIMG4):
    def __init__(
        self,
        data: Optional[bytes] = None,
        *,
        fourcc: Optional[str] = None,
        value: Any = None,
    ) -> None:
        super().__init__(data)

        if fourcc is not None and value is not None:
            self._fourcc = self._verify_fourcc(fourcc)
            self._value = value

        elif data:
            self._parse()

        else:
            raise TypeError('No data or fourcc/value pair provided.')

    def __repr__(self) -> str:
        if (
            not isinstance(self.value, (float, int, type(None)))
            and len(self.value) > 15
        ):
            value = f'<{type(self.value).__name__} with len of {len(self.value)}>'
        elif isinstance(self.value, bytes):
            value = self.value.hex()
        else:
            value = self.value

        return f'{type(self).__name__}({self.fourcc}={value})'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._fourcc = self._verify_fourcc(self._decoder.read()[1])
        self._value = self._decoder.read()[1]

    @property
    def fourcc(self) -> str:
        return self._fourcc

    @property
    def value(self) -> Any:
        return self._value

    def output(self) -> bytes:
        self._encoder.start()
        with self._encoder.construct(
            int(bytes(self.fourcc, 'ascii').hex(), 16), asn1.Classes.Private
        ):
            with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
                self._encoder.write(
                    self.fourcc,
                    asn1.Numbers.IA5String,
                    asn1.Types.Primitive,
                    asn1.Classes.Universal,
                )

                self._encoder.write(
                    self.value, None, asn1.Types.Primitive, asn1.Classes.Universal
                )

        return self._encoder.output()


class _PropertyGroup(_PyIMG4):
    _property = _Property

    def __init__(
        self, data: Optional[bytes] = None, *, fourcc: Optional[str] = None
    ) -> None:
        super().__init__(data)

        self._properties: List[Optional[self._property]] = []

        if data:
            self._parse()

        elif fourcc:
            self._fourcc = self._verify_fourcc(fourcc)

        else:
            raise TypeError('No data or fourcc provided.')

    def __repr__(self) -> str:
        return f'{type(self).__name__}(fourcc={self.fourcc})'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()

        self._fourcc = self._verify_fourcc(self._decoder.read()[1])

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()

        while not self._decoder.eof():
            self._properties.append(self._property(self._decoder.read()[1]))

    @property
    def fourcc(self) -> str:
        return self._fourcc

    @property
    def properties(self) -> Tuple[Optional[_property]]:
        return tuple(self._properties)

    def add_property(self, prop: _property) -> None:
        if not isinstance(prop, self._property):
            raise UnexpectedDataError(self._property.__name__, prop)

        if any(p.fourcc == prop.fourcc for p in self.properties):
            raise ValueError(f'Property "{prop.fourcc}" already exists.')

        self._properties.append(prop)

    def remove_property(
        self, prop: Optional[_property] = None, fourcc: Optional[str] = None
    ) -> None:
        if prop is not None:
            if not isinstance(prop, self._property):
                raise UnexpectedDataError(self._property.__name__, prop)

            if prop not in self.properties:
                raise ValueError(f'Property "{prop.fourcc}" is not set')

            self._properties.remove(prop)

        elif fourcc is not None:
            self._verify_fourcc(fourcc)

            prop = next(
                (prop for prop in self.properties if prop.fourcc == fourcc), None
            )
            if prop is not None:
                self._properties.remove(prop)
            else:
                raise ValueError(f'Property "{fourcc}" is not set')

        else:
            raise TypeError(f'No {self._property.__name__} or fourcc provided.')

    def output(self) -> bytes:
        if len(self.properties) == 0:
            raise ValueError('No properties are set')

        self._encoder.start()
        with self._encoder.construct(
            int(bytes(self.fourcc, 'ascii').hex(), 16), asn1.Classes.Private
        ):
            with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
                self._encoder.write(
                    self.fourcc,
                    asn1.Numbers.IA5String,
                    asn1.Types.Primitive,
                    asn1.Classes.Universal,
                )

                with self._encoder.construct(asn1.Numbers.Set, asn1.Classes.Universal):
                    for prop in self.properties:
                        self._decoder.start(prop.output())
                        with self._encoder.construct(
                            self._decoder.peek().nr, asn1.Classes.Private
                        ):
                            self._decoder.enter()
                            self._encoder.write(
                                self._decoder.read()[1],
                                asn1.Numbers.Sequence,
                                asn1.Types.Constructed,
                                asn1.Classes.Universal,
                            )

        return self._encoder.output()


class Data(_PyIMG4):
    def get_type(self) -> Optional[Union['IMG4', 'IM4P', 'IM4M', 'IM4R']]:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()

        fourcc = self._verify_fourcc(self._decoder.read()[1])
        if fourcc == 'IMG4':
            return IMG4
        elif fourcc == 'IM4P':
            return IM4P
        elif fourcc == 'IM4M':
            return IM4M
        elif fourcc == 'IM4R':
            return IM4R


class ManifestProperty(_Property):
    pass


class ManifestImageProperties(_PropertyGroup):
    _property = ManifestProperty

    @property
    def digest(self) -> Optional[bytes]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'DGST'),
            None,
        )


class IM4M(_PyIMG4):
    def __init__(self, data: Optional[bytes] = None) -> None:
        super().__init__(data)

        self._images: List[ManifestImageProperties] = []
        self._properties: List[ManifestProperty] = []

        if data:
            self._parse()

    def __repr__(self) -> str:
        repr_ = 'IM4M('
        for p in ('CHIP', 'ECID'):
            prop = next((prop for prop in self.properties if prop.fourcc == p), None)

            if prop is not None:
                repr_ += f'{prop.fourcc}={prop.value}, '

        return f'{repr_[:-2]})' if ',' in repr_ else f'{repr_})'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(self._decoder.read()[1], 'IM4M')

        if self._decoder.read()[0].nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Integer)

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()

        if self._decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Private)

        self._decoder.enter()

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(
            self._decoder.read()[1], 'MANB'
        )  # Verify MANB (Manifest Body) FourCC

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()
        while not self._decoder.eof():
            data = ManifestImageProperties(self._decoder.read()[1])
            if data.fourcc == 'MANP':
                self._properties = list(data.properties)
            else:
                self._images.append(data)

        for _ in range(4):
            self._decoder.leave()

        if self._decoder.eof():
            # IM4M has no signature/certificates
            # TODO: Make this cleaner
            self._signature = None
            self._certificates = None
            return

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        self._signature = self._decoder.read()[1]

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        # TODO: Parse certificates
        self._certificates = self._decoder.read()[1]

        if not self._decoder.eof():
            raise ValueError(
                f'Unexpected data found at end of Image4 manifest: {self._decoder.peek().nr.name.upper()}'
            )

    @property
    def apnonce(self) -> Optional[bytes]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'BNCH'),
            None,
        )

    @property
    def board_id(self) -> Optional[int]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'BORD'), None
        )

    @property
    def certificates(self) -> bytes:
        return self._certificates

    @property
    def chip_id(self) -> Optional[int]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'CHIP'), None
        )

    @property
    def ecid(self) -> Optional[int]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'ECID'), None
        )

    @property
    def images(self) -> Tuple[Optional[ManifestImageProperties]]:
        return tuple(self._images)

    @property
    def properties(self) -> Tuple[Optional[ManifestProperty]]:
        return tuple(self._properties)

    @property
    def sepnonce(self) -> Optional[bytes]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'snon'),
            None,
        )

    @property
    def signature(self) -> bytes:
        return self._signature

    def add_image_properties(self, image_properties: ManifestImageProperties) -> None:
        if not isinstance(image_properties, ManifestImageProperties):
            raise UnexpectedDataError(
                ManifestImageProperties.__name__, image_properties
            )

        if any(image.fourcc == image_properties.fourcc for image in self.images):
            raise ValueError(
                f'Properties for image "{image_properties.fourcc}" already exist.'
            )

        self._images.append(image_properties)
        self._images.sort()

    def remove_image_properties(
        self,
        image_properties: Optional[ManifestImageProperties] = None,
        fourcc: Optional[str] = None,
    ) -> None:
        if image_properties is not None:
            if not isinstance(image_properties, ManifestImageProperties):
                raise UnexpectedDataError(
                    ManifestImageProperties.__name__, image_properties
                )

            if image_properties not in self.images:
                raise ValueError(
                    f'Properties for image "{image_properties.fourcc}" are not set'
                )

            self._images.remove(image_properties)
            self._images.sort()

        elif fourcc is not None:
            self._verify_fourcc(fourcc)

            image_properties = next(
                (image for image in self.images if image.fourcc == fourcc), None
            )
            if image_properties is None:
                raise ValueError(f'Properties for image "{fourcc}" are not set')

            self._images.remove(image_properties)
            self._images.sort()
        else:
            raise TypeError('No ManifestImageProperties or fourcc provided.')

    def add_property(self, prop: ManifestProperty) -> None:
        if not isinstance(prop, ManifestProperty):
            raise UnexpectedDataError(ManifestProperty.__name__, prop)

        if any(p.fourcc == prop.fourcc for p in self.properties):
            raise ValueError(f'Property "{prop.fourcc}" already exists.')

        self._properties.append(prop)

    def remove_property(
        self, prop: Optional[ManifestProperty] = None, fourcc: Optional[str] = None
    ) -> None:
        if prop is not None:
            if not isinstance(prop, ManifestProperty):
                raise UnexpectedDataError(ManifestProperty.__name__, prop)

            if prop not in self.properties:
                raise ValueError(f'Property "{prop.fourcc}" is not set')

            self._properties.remove(prop)

        elif fourcc is not None:
            self._verify_fourcc(fourcc)

            prop = next(
                (prop for prop in self.properties if prop.fourcc == fourcc), None
            )
            if prop is not None:
                self._properties.remove(prop)
            else:
                raise ValueError(f'Property "{fourcc}" is not set')

        else:
            raise TypeError('No ManifestProperty or fourcc provided.')

    def output(self) -> bytes:
        if len(self.properties) == 0:
            raise ValueError('No properties are set')

        if len(self.images) == 0:
            raise ValueError('No images are set')

        self._encoder.start()
        with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
            self._encoder.write(
                'IM4M',
                asn1.Numbers.IA5String,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            self._encoder.write(
                0,
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            with self._encoder.construct(asn1.Numbers.Set, asn1.Classes.Universal):
                manp = ManifestImageProperties(fourcc='MANP')
                for prop in self.properties:
                    manp.add_property(prop)

                manb = ManifestImageProperties(fourcc='MANB')
                manb._properties = [manp, *self.images]
                self._decoder.start(manb.output())
                with self._encoder.construct(
                    self._decoder.peek().nr, asn1.Classes.Private
                ):
                    self._decoder.enter()
                    self._encoder.write(
                        self._decoder.read()[1],
                        asn1.Numbers.Sequence,
                        asn1.Types.Constructed,
                        asn1.Classes.Universal,
                    )

            self._encoder.write(
                self.signature,
                asn1.Numbers.OctetString,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            self._encoder.write(
                self.certificates,
                asn1.Numbers.Sequence,
                asn1.Types.Constructed,
                asn1.Classes.Universal,
            )
        return self._encoder.output()


class RestoreProperty(_Property):
    pass


class IM4R(_PropertyGroup):
    _property = RestoreProperty

    def __init__(self, data: Optional[bytes] = None) -> None:
        super().__init__(data, fourcc='IM4R')

        if self.boot_nonce is not None:
            self.boot_nonce = self.boot_nonce[::-1]

    def __repr__(self) -> str:
        return f'IM4R(properties={len(self.properties)})'

    @property
    def boot_nonce(self) -> Optional[bytes]:
        return next(
            (prop.value for prop in self.properties if prop.fourcc == 'BNCN'),
            None,
        )

    @boot_nonce.setter
    def boot_nonce(self, boot_nonce: bytes) -> None:
        if not isinstance(boot_nonce, bytes):
            raise UnexpectedDataError('bytes', boot_nonce)

        if len(boot_nonce) != 8:
            raise UnexpectedDataError('bytes with length of 8', boot_nonce)

        prop = next((p for p in self.properties if p.fourcc == 'BNCN'), None)
        if prop is not None:
            self.remove_property(prop)

        self.add_property(RestoreProperty(fourcc='BNCN', value=boot_nonce))

    def output(self) -> bytes:
        if len(self.properties) == 0:
            raise ValueError('No properties are set')

        self._encoder.start()
        with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
            self._encoder.write(
                self.fourcc,
                asn1.Numbers.IA5String,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            with self._encoder.construct(asn1.Numbers.Set, asn1.Classes.Universal):
                if self.boot_nonce is not None:
                    self.boot_nonce = self.boot_nonce[::-1]

                for prop in self.properties:
                    self._decoder.start(prop.output())
                    with self._encoder.construct(
                        self._decoder.peek().nr, asn1.Classes.Private
                    ):
                        self._decoder.enter()
                        self._encoder.write(
                            self._decoder.read()[1],
                            asn1.Numbers.Sequence,
                            asn1.Types.Constructed,
                            asn1.Classes.Universal,
                        )

        return self._encoder.output()


class IMG4(_PyIMG4):
    def __init__(
        self,
        data: Optional[bytes] = None,
        *,
        im4p: Optional[Union['IM4P', bytes]] = None,
        im4m: Optional[Union[IM4M, bytes]] = None,
        im4r: Optional[Union[IM4R, bytes]] = None,
    ) -> None:
        super().__init__(data)

        if data:
            self._parse()
        else:
            self.im4p = im4p
            self.im4m = im4m
            self.im4r = im4r

    def __repr__(self) -> str:
        if self.im4p is not None:
            return f'IMG4(fourcc={self.im4p.fourcc}, description="{self.im4p.description}")'
        else:
            return 'IMG4()'

    def _parse(self) -> None:
        self._decoder.start(self._data)
        self._encoder.start()

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(self._decoder.read()[1], 'IMG4')  # Verify IMG4 FourCC

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._encoder.write(
            self._decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4p = IM4P(self._encoder.output())  # IM4P

        if self._decoder.peek().cls != asn1.Classes.Context:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Context)

        self.im4m = IM4M(self._decoder.read()[1])  # IM4M

        if self._decoder.eof():
            self.im4r = None

        elif self._decoder.peek().cls != asn1.Classes.Context:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Context)

        else:
            self.im4r = IM4R(self._decoder.read()[1])  # IM4R
        if not self._decoder.eof():
            raise ValueError(
                f'Unexpected data found at end of Image4: {self._decoder.peek().nr.name.upper()}'
            )

    @property
    def im4m(self) -> Optional[IM4M]:
        return self._im4m

    @im4m.setter
    def im4m(self, im4m: Optional[Union[IM4M, bytes]]) -> None:
        if im4m is not None and not isinstance(im4m, (IM4M, bytes)):
            raise UnexpectedDataError('IM4M or bytes', im4m)

        self._im4m = IM4M(im4m) if isinstance(im4m, bytes) else im4m

    @property
    def im4p(self) -> Optional['IM4P']:
        return self._im4p

    @im4p.setter
    def im4p(self, im4p: Optional[Union['IM4P', bytes]]) -> None:
        if im4p is not None and not isinstance(im4p, (IM4P, bytes)):
            raise UnexpectedDataError('IM4P or bytes', im4p)

        self._im4p = IM4P(im4p) if isinstance(im4p, bytes) else im4p

    @property
    def im4r(self) -> Optional[IM4R]:
        return self._im4r

    @im4r.setter
    def im4r(self, im4r: Optional[Union[IM4R, bytes]]) -> None:
        if im4r is not None and not isinstance(im4r, (IM4R, bytes)):
            raise UnexpectedDataError('IM4R or bytes', im4r)

        self._im4r = IM4R(im4r) if isinstance(im4r, bytes) else im4r

    def output(self) -> bytes:
        self._encoder.start()

        with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
            self._encoder.write(
                'IMG4',
                asn1.Numbers.IA5String,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            if self.im4p is None:
                raise ValueError('No IM4P is set.')

            self._decoder.start(self.im4p.output())
            self._encoder.write(
                self._decoder.read()[1],
                asn1.Numbers.Sequence,
                asn1.Types.Constructed,
                asn1.Classes.Universal,
            )

            if self.im4m is None:
                raise ValueError('No IM4M is set.')

            self._encoder.write(
                self.im4m.output(),
                0,
                asn1.Types.Constructed,
                asn1.Classes.Context,
            )

            if self.im4r is not None:
                self._encoder.write(
                    self.im4r.output(),
                    1,
                    asn1.Types.Constructed,
                    asn1.Classes.Context,
                )

        return self._encoder.output()


class PayloadProperty(_Property):
    pass


class IM4P(_PyIMG4):
    def __init__(
        self,
        data: Optional[bytes] = None,
        *,
        fourcc: Optional[str] = None,
        description: Optional[str] = None,
        payload: Optional[Union['IM4PData', bytes]] = None,
    ) -> None:
        super().__init__(data)

        self._properties = []

        if data:
            self._parse()
        else:
            self.fourcc = fourcc
            self.description = description
            self.payload = payload

    def __add__(self, im4m: IM4M) -> IMG4:
        if isinstance(im4m, IM4M):
            return IMG4(im4m=im4m, im4p=self)
        else:
            raise TypeError(
                f'can only concatenate IM4M (not "{type(im4m).__name__}") to IM4P'
            )

    __radd__ = __add__

    def __repr__(self) -> str:
        return f'IM4P(fourcc={self.fourcc}, description="{self.description}")'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(
            self._decoder.read()[1], 'IM4P'
        )  # Verify IM4P (IMG4 Payload) FourCC

        if self._decoder.peek().nr != asn1.Numbers.IA5String:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.IA5String)

        self.fourcc = self._verify_fourcc(
            self._decoder.read()[1]
        )  # Will raise error if FourCC is invalid

        if self._decoder.peek().nr != asn1.Numbers.IA5String:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.IA5String)

        self.description = self._decoder.read()[1]

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        self.payload = self._decoder.read()[1]

        if (
            not self._decoder.eof()
            and self._decoder.peek().nr == asn1.Numbers.OctetString
        ):
            kbag_decoder = asn1.Decoder()
            kbag_decoder.start(self._decoder.read()[1])

            if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

            kbag_decoder.enter()

            while not kbag_decoder.eof():
                if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                    raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

                self.payload.add_keybag(Keybag(kbag_decoder.read()[1]))

        if not self._decoder.eof() and self._decoder.peek().nr == asn1.Numbers.Sequence:
            self._decoder.enter()

            if (
                self._decoder.peek().nr == asn1.Numbers.Integer
                and self._decoder.read()[1] == 1
            ):
                self.payload.size = self._decoder.read()[1]

            self._decoder.leave()

        if not self._decoder.eof() and self._decoder.peek().cls == asn1.Classes.Context:
            self._decoder.enter()

            if self._decoder.peek().nr != asn1.Numbers.Sequence:
                raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

            self._decoder.enter()
            self._verify_fourcc(self._decoder.read()[1], 'PAYP')

            if self._decoder.peek().nr != asn1.Numbers.Set:
                raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

            self._decoder.enter()
            while not self._decoder.eof():
                self._properties.append(PayloadProperty(self._decoder.read()[1]))

        if not self._decoder.eof():
            raise ValueError(
                f'Unexpected data found at end of Image4 payload: {self._decoder.peek().nr.name.upper()}'
            )

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, description: Optional[str]) -> None:
        if description is not None and not isinstance(description, str):
            raise UnexpectedDataError('string', description)

        self._description = description or ''

    @property
    def fourcc(self) -> Optional[str]:
        return self._fourcc

    @fourcc.setter
    def fourcc(self, fourcc: Optional[str]) -> None:
        if fourcc is None:
            self._fourcc = fourcc

        elif isinstance(fourcc, str):
            self._fourcc = self._verify_fourcc(fourcc)
        else:
            raise UnexpectedDataError('string', fourcc)

    @property
    def payload(self) -> Optional['IM4PData']:
        return self._payload

    @payload.setter
    def payload(self, payload: Optional[Union['IM4PData', bytes]]) -> None:
        if payload is not None and not isinstance(payload, (IM4PData, bytes)):
            raise UnexpectedDataError('IM4PData or bytes', payload)

        self._payload = IM4PData(payload) if isinstance(payload, bytes) else payload

    @property
    def properties(self) -> Tuple[Optional[PayloadProperty]]:
        return tuple(self._properties)

    def add_property(self, prop: PayloadProperty) -> None:
        if not isinstance(prop, PayloadProperty):
            raise UnexpectedDataError(PayloadProperty.__name__, prop)

        if any(p.fourcc == prop.fourcc for p in self.properties):
            raise ValueError(f'Property "{prop.fourcc}" already exists.')

        self._properties.append(prop)

    def remove_property(
        self, prop: Optional[PayloadProperty] = None, fourcc: Optional[str] = None
    ) -> None:
        if prop is not None:
            if not isinstance(prop, PayloadProperty):
                raise UnexpectedDataError('PayloadProperty', prop)

            if prop not in self.properties:
                raise ValueError(f'Property "{prop.fourcc}" is not set')

        elif fourcc is not None:
            self._verify_fourcc(fourcc)

            prop = next(
                (prop for prop in self.properties if prop.fourcc == fourcc), None
            )
            if prop is not None:
                self._properties.remove(prop)
            else:
                raise ValueError(f'Property "{fourcc}" not found')

    def output(self) -> bytes:
        self._encoder.start()

        with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
            self._encoder.write(
                'IM4P',
                asn1.Numbers.IA5String,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            if self.fourcc is None:
                raise ValueError('No fourcc is set.')

            self._encoder.write(
                self.fourcc,
                asn1.Numbers.IA5String,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            self._encoder.write(
                self.description,
                asn1.Numbers.IA5String,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            if self.payload is None:
                raise ValueError('No payload is set.')

            for i in self.payload.output():
                if i is None:
                    continue

                self._encoder.write(
                    i,
                    asn1.Numbers.OctetString,
                    asn1.Types.Primitive,
                    asn1.Classes.Universal,
                )

            if self.payload.compression in (
                Compression.LZFSE,
                Compression.LZFSE_ENCRYPTED,
            ):
                with self._encoder.construct(
                    asn1.Numbers.Sequence, asn1.Classes.Universal
                ):
                    self._encoder.write(
                        1,
                        asn1.Numbers.Integer,
                        asn1.Types.Primitive,
                        asn1.Classes.Universal,
                    )

                    self._encoder.write(
                        self.payload.size,
                        asn1.Numbers.Integer,
                        asn1.Types.Primitive,
                        asn1.Classes.Universal,
                    )

            if len(self.properties) > 0:
                with self._encoder.construct(0, asn1.Classes.Context):
                    with self._encoder.construct(
                        asn1.Numbers.Sequence, asn1.Classes.Universal
                    ):
                        self._encoder.write(
                            'PAYP',
                            asn1.Numbers.IA5String,
                            asn1.Types.Primitive,
                            asn1.Classes.Universal,
                        )

                        with self._encoder.construct(
                            asn1.Numbers.Set, asn1.Classes.Universal
                        ):
                            for prop in self.properties:
                                self._decoder.start(prop.output())
                                with self._encoder.construct(
                                    self._decoder.peek().nr, asn1.Classes.Private
                                ):
                                    self._decoder.enter()
                                    self._encoder.write(
                                        self._decoder.read()[1],
                                        asn1.Numbers.Sequence,
                                        asn1.Types.Constructed,
                                        asn1.Classes.Universal,
                                    )

        return self._encoder.output()


class Keybag(_PyIMG4):
    def __init__(
        self,
        data: Optional[bytes] = None,
        *,
        iv: bytes = None,
        key: bytes = None,
        type_: KeybagType = KeybagType.PRODUCTION,  # Assume PRODUCTION if not provided
    ) -> None:
        super().__init__(data)

        if iv and key:
            self.iv = iv
            self.key = key
            self.type = type_

        elif data:
            self._parse()

        else:
            raise TypeError('No data or IV/Key provided.')

    def __repr__(self) -> str:
        return (
            f'Keybag(iv={self.iv.hex()}, key={self.key.hex()}, type={self.type.name})'
        )

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Integer)

        self.type = KeybagType(self._decoder.read()[1])

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        self.iv = self._decoder.read()[1]

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        self.key = self._decoder.read()[1]

        if not self._decoder.eof():
            raise ValueError(
                f'Unexpected data found at end of keybag: {self._decoder.peek().nr.name.upper()}'
            )

    @property
    def iv(self) -> bytes:
        return self._iv

    @iv.setter
    def iv(self, iv: bytes) -> None:
        if not isinstance(iv, bytes):
            raise UnexpectedDataError('bytes', iv)

        if len(iv) != 16:
            raise UnexpectedDataError('bytes with len of 16', iv)

        self._iv = iv

    @property
    def key(self) -> bytes:
        return self._key

    @key.setter
    def key(self, key: bytes) -> None:
        if not isinstance(key, bytes):
            raise UnexpectedDataError('bytes', key)

        if len(key) != 32:
            raise UnexpectedDataError('bytes with len of 32', key)

        self._key = key

    @property
    def type(self) -> KeybagType:
        return self._type

    @type.setter
    def type(self, type_: KeybagType) -> None:
        if not isinstance(type_, KeybagType):
            raise UnexpectedDataError('KeybagType', type_)

        self._type = type_


class IM4PData(_PyIMG4):
    def __init__(
        self, data: bytes, *, size: int = 0, extra: Optional[bytes] = None
    ) -> None:
        super().__init__(data)

        self._keybags = []
        self.extra = extra

        self._detect_compression(size, data)
        if self.compression == Compression.LZSS:
            self._parse_complzss_header()
        elif self.compression == Compression.LZFSE:
            self.size = len(self._decompress_data(data, self.compression, size))
        else:
            self.size = size

    def __len__(self) -> int:
        return len(self.data)

    def __repr__(self) -> str:
        repr_ = f'IM4PData(payload length={hex(len(self))}, encrypted={self.encrypted}'
        if self.compression != Compression.NONE:
            repr_ += f', compression={self.compression.name}'

        return f'{repr_})'

    def _create_complzss_header(self, comp_size: int) -> bytes:
        header = bytearray(b'complzss')
        header += adler32(self.data).to_bytes(4, 'big')
        header += self.size.to_bytes(4, 'big')
        header += comp_size.to_bytes(4, 'big')
        header += int(1).to_bytes(4, 'big')
        header += bytearray(0x180 - len(header))

        return bytes(header)

    def _decompress_data(
        self, data: bytes, compression: Compression, size: Optional[int] = None
    ) -> bytes:
        if compression == Compression.LZSS:
            return lzss.decompress(data)

        elif self.compression == Compression.LZFSE:
            return _lzfse_decompress(self.data, size)

    def _detect_compression(self, size: int, data: bytes) -> None:
        if self.encrypted and size > 0:
            self._compression = Compression.LZFSE_ENCRYPTED

        elif data.startswith(b'complzss'):
            self._compression = Compression.LZSS

        elif data.startswith(b'bvx') and b'bvx$' in self.data:
            self._compression = Compression.LZFSE

        else:
            self._compression = Compression.NONE

    def _parse_complzss_header(self) -> None:
        self.size = int(self.data[0xC:0x10].hex(), 16)
        cmp_len = int(self.data[0x10:0x14].hex(), 16)

        if (
            cmp_len < len(self.data) - 0x180
        ):  # iOS 9+ A7-A9 kernelcache, so KPP is appended to the LZSS-compressed data
            extra_len = len(self.data) - cmp_len - 0x180
            self.extra = self.data[-extra_len:]

            self._data = self.data[:-extra_len]

    @property
    def compression(self) -> Compression:
        return self._compression

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def encrypted(self) -> bool:
        return len(self.keybags) > 0

    @property
    def extra(self) -> Optional[bytes]:
        return self._extra

    @extra.setter
    def extra(self, extra: Optional[bytes]) -> None:
        if extra is not None and not isinstance(extra, bytes):
            raise UnexpectedDataError('bytes', extra)

        self._extra = extra

    @property
    def keybags(self) -> Tuple[Optional[Keybag]]:
        return tuple(self._keybags)

    @property
    def size(self) -> int:
        return self._size

    @size.setter
    def size(self, size: int) -> None:
        if not isinstance(size, int):
            raise UnexpectedDataError('int', size)

        if size < 0:
            raise ValueError('Size cannot be less than 0.')

        if 0 < size < len(self.data):
            raise ValueError('Size cannot be less than the length of the payload data.')

        if self.encrypted is True:
            self._detect_compression(size, self.data)

        self._size = size

    def add_keybag(self, keybag: Keybag) -> None:
        if not isinstance(keybag, Keybag):
            raise UnexpectedDataError('Keybag', keybag)

        if any(kbag.type == keybag.type for kbag in self.keybags):
            raise ValueError(
                f'There is already a {keybag.type.name.lower()} keybag added.'
            )

        if any(kbag == keybag for kbag in self.keybags):
            raise ValueError('This keybag already exists.')

        self._keybags.append(keybag)

    def remove_keybag(
        self, keybag: Optional[Keybag] = None, type_: Optional[KeybagType] = None
    ) -> None:
        if keybag is not None:
            if not isinstance(keybag, keybag):
                raise UnexpectedDataError('Keybag', keybag)

            if keybag not in self._keybags:
                raise ValueError('Keybag has not been added.')

            self._keybags.remove(keybag)

        elif type_ is not None:
            keybag = next(
                (kbag for kbag in self.properties if kbag.type == type_), None
            )
            if keybag is not None:
                self._keybags.remove(keybag)
            else:
                raise ValueError(f'There is no {type_.name.lower()} keybag added.')

    def compress(self, compression: Compression) -> None:
        if compression in (
            Compression.NONE,
            Compression.LZFSE_ENCRYPTED,
        ):
            raise ValueError('A valid compression type must be specified.')

        if self.encrypted is True:
            raise CompressionError('Cannot compress encrypted payload.')

        elif self.compression in (Compression.LZSS, Compression.LZFSE):
            raise CompressionError(f'Payload is already {compression.name}-compressed.')

        self.size = len(self.data)
        if compression == Compression.LZSS:
            comp_data = lzss.compress(self.data)
            self._data = self._create_complzss_header(len(comp_data)) + comp_data

        elif compression == Compression.LZFSE:
            comp_data = _lzfse_compress(self.data)
            if not (comp_data.startswith(b'bvx2') and b'bvx$' in comp_data):
                raise CompressionError('Failed to LZFSE-compress payload.')

            self._data = comp_data

        self._detect_compression(self.size, self.data)

    def decompress(self) -> None:
        if self.compression == Compression.NONE:
            raise CompressionError('Payload is not compressed.')

        elif self.compression == Compression.LZFSE_ENCRYPTED:
            raise CompressionError('Cannot decompress encrypted payload.')

        self._data = self._decompress_data(self.data, self.compression, self.size)
        self._compression = Compression.NONE
        self._detect_compression(self.size, self.data)

    def decrypt(self, kbag: Keybag) -> None:
        self._data = AES.new(kbag.key, AES.MODE_CBC, kbag.iv).decrypt(self.data)
        self._keybags = []
        self._detect_compression(self.size, self.data)

        if self.compression == Compression.LZSS:
            self._parse_complzss_header()
        elif self.compression == Compression.LZFSE:
            self.size = len(self._decompress_data(self.data, self.compression))

    def output(self) -> Payload:
        kbag_data = None
        if self.encrypted:
            self._encoder.start()
            with self._encoder.construct(asn1.Numbers.Sequence, asn1.Classes.Universal):
                for kbag in self.keybags:
                    with self._encoder.construct(
                        asn1.Numbers.Sequence, asn1.Classes.Universal
                    ):
                        self._encoder.write(
                            self.keybags.index(kbag) + 1,
                            asn1.Numbers.Integer,
                            asn1.Types.Primitive,
                            asn1.Classes.Universal,
                        )
                        self._encoder.write(
                            kbag.iv,
                            asn1.Numbers.OctetString,
                            asn1.Types.Primitive,
                            asn1.Classes.Universal,
                        )
                        self._encoder.write(
                            kbag.key,
                            asn1.Numbers.OctetString,
                            asn1.Types.Primitive,
                            asn1.Classes.Universal,
                        )

            kbag_data = self._encoder.output()

        if self.extra is not None:
            data = self.data + self.extra
        else:
            data = self.data

        return Payload(data, kbag_data)
